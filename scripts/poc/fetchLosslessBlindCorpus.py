#!/usr/bin/env python3
"""Freeze a second, not-previously-inspected public source-file evaluation set."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import urllib.request


PINNED = "ee918d03f4a90dacd32673546c64a633308796ef"
FILES = [
    "packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet-7-2.log",
    "packages/zscaler_zia/data_stream/firewall/_dev/test/pipeline/test-unicode.json",
    "packages/suricata/data_stream/eve/_dev/test/pipeline/test-eve-small.log",
    "packages/cisco_asa/data_stream/log/_dev/test/pipeline/test-106023-iface-with-prefix.log",
    "packages/cisco_asa/data_stream/log/_dev/test/pipeline/test-302020-direction.log",
    "packages/sonicwall_firewall/data_stream/log/_dev/test/pipeline/test-sonicos70-aws.log",
    "packages/sonicwall_firewall/data_stream/log/_dev/test/pipeline/test-drizzthacker.log",
    "packages/aws/data_stream/cloudtrail/_dev/test/pipeline/test-attach-group-policy-json.log",
    "packages/zscaler_zia/data_stream/firewall/_dev/test/pipeline/test-firewall-http-endpoint.log",
]
DEST = Path.home()/".local/state/parserstudio-lossless-blind-20261017"
MANIFEST = Path(__file__).resolve().parent/"losslessGrammarBlind.manifest.json"


def write_once(filename: str, payload: bytes) -> None:
    p=DEST/filename
    if p.exists():
        if p.read_bytes()!=payload:
            raise ValueError(f"Refusing to alter source evidence {filename}")
        return
    with p.open("xb") as handle:
        handle.write(payload)
    os.chmod(p,0o600)


def main() -> None:
    DEST.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(DEST,0o700)
    expected=json.loads(MANIFEST.read_text())
    if expected["revision"]!=PINNED or (
        [entry["path"] for entry in expected["files"]]!=FILES
    ):
        raise ValueError("Pinned blind source selection differs")
    records=[]
    source=[]
    for path in FILES:
        req=urllib.request.Request(
            f"https://raw.githubusercontent.com/elastic/integrations/{PINNED}/{path}",
            headers={"User-Agent":"ParserStudio-Lossless-Blind-PoC/1.0"},
        )
        data=urllib.request.urlopen(req,timeout=25).read()
        if len(data)>2*1024*1024:
            raise ValueError(f"Unexpectedly large source fixture {path}")
        recorded=expected["files"][len(source)]
        if len(data)!=recorded["bytes"] or (
            hashlib.sha256(data).hexdigest()!=recorded["sha256"]
        ):
            raise ValueError(f"Blind upstream source hash drift: {path}")
        text=data.decode("utf-8-sig")
        candidate=text.strip()
        if candidate.startswith(("{","[")):
            try:
                value=json.loads(candidate)
                rows=[candidate] if isinstance(value,(dict,list)) else []
            except json.JSONDecodeError:
                rows=[line for line in text.splitlines() if line.strip()]
        else:
            rows=[line for line in text.splitlines() if line.strip()]
        if not rows or len(rows)!=recorded["events"]:
            raise ValueError(f"Blind source record count drift: {path}")
        for index,row in enumerate(rows,1):
            records.append({"id":f"{path.split('/')[1]}/{Path(path).name}#{index}",
                "source":path,"raw":row})
        source.append({"path":path,"sha256":hashlib.sha256(data).hexdigest(),
            "bytes":len(data),"events":len(rows)})
    encoded=json.dumps(records,ensure_ascii=False,sort_keys=True).encode()
    summary={"revision":PINNED,"files":source,"events":len(records),
        "record_sha256":hashlib.sha256(encoded).hexdigest(),
        "frozen_before": "first-blind-evaluation"}
    if summary!=expected:
        raise ValueError("Frozen blind corpus hash or metadata drift")
    manifest_path=DEST/"manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text())!=expected:
        raise ValueError("Frozen blind local metadata conflicts with repository")
    write_once("records.json",encoded)
    write_once("manifest.json",(
        manifest_path.read_bytes() if manifest_path.exists()
        else json.dumps(summary,indent=2).encode()
    ))
    print(json.dumps({"files":len(source),"events":len(records),
      "record_sha256":summary["record_sha256"],
      "distribution":{Path(f["path"]).name:f["events"] for f in source}}))


if __name__=="__main__":
    main()
