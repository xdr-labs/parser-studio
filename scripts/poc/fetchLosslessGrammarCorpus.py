#!/usr/bin/env python3
"""Download immutable, checksum-pinned upstream public security fixtures privately."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT/"losslessGrammar.manifest.json"
SPLIT = ROOT/"losslessGrammar.split.json"
DEST = Path.home()/".local/state/parserstudio-lossless-fresh-20261017"


def frozen_write(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError(f"Refusing to overwrite frozen file: {path}")
        return
    with path.open("xb") as writer:
        writer.write(payload)
    os.chmod(path, 0o600)


def main() -> None:
    manifest = json.loads(MANIFEST.read_text())
    split = json.loads(SPLIT.read_text())
    revision = manifest["revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Noncanonical upstream source revision")
    DEST.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DEST, 0o700)
    records: list[dict[str, str]] = []
    files = manifest["files"]
    for fixture in files:
        source = fixture["path"]
        if not source.startswith("packages/") or ".." in Path(source).parts:
            raise ValueError("Untrusted source path")
        req = urllib.request.Request(
            f"https://raw.githubusercontent.com/elastic/integrations/{revision}/{source}",
            headers={"User-Agent":"ParserStudio-Lossless-PoC/1.0"},
        )
        payload = urllib.request.urlopen(req, timeout=30).read()
        if len(payload) != fixture["bytes"] or (
            hashlib.sha256(payload).hexdigest() != fixture["sha256"]
        ):
            raise ValueError(f"Upstream source checksum drift: {source}")
        text = payload.decode("utf-8-sig")
        candidate = text.strip()
        if candidate.startswith(("{", "[")):
            try:
                parsed = json.loads(candidate)
                chunks = [candidate] if isinstance(parsed, (dict, list)) else []
            except json.JSONDecodeError:
                chunks = [line for line in text.splitlines() if line.strip()]
        else:
            chunks = [line for line in text.splitlines() if line.strip()]
        if len(chunks) != fixture["logical_or_line_records"]:
            raise ValueError(f"Expected event framing changed: {source}")
        for number, raw in enumerate(chunks, 1):
            if len(raw.encode()) > 16384:
                raise ValueError(f"Source exceeds PoC bounded record size: {source}")
            records.append({
                "id": f"{source.split('/')[1]}/{Path(source).name}#{number}",
                "source": source,
                "raw": raw,
            })
    serial=json.dumps(records, ensure_ascii=False, sort_keys=True).encode()
    checksum=hashlib.sha256(serial).hexdigest()
    if checksum!=manifest["records_sha256"] or len(records)!=manifest["events"]:
        raise ValueError("Frozen logical record set differs")
    if split["events_sha256"]!=checksum or (
        split["development_events"]+split["evaluation_events"]!=len(records)
    ):
        raise ValueError("Frozen train/evaluation split differs")
    for name, pinned in (("manifest.json", manifest), ("split.json", split)):
        existing = DEST/name
        if existing.exists() and json.loads(existing.read_text()) != pinned:
            raise ValueError(f"Private frozen metadata differs from repository: {name}")
    for name,payload in [
        ("records.json",serial),
        ("manifest.json",(DEST/"manifest.json").read_bytes() if
            (DEST/"manifest.json").exists() else json.dumps(manifest,indent=2).encode()),
        ("split.json",(DEST/"split.json").read_bytes() if
            (DEST/"split.json").exists() else json.dumps(split,indent=2).encode()),
    ]:
        frozen_write(DEST/name,payload)
    print(json.dumps({"files":len(files),"events":len(records),
        "record_sha256":checksum,"private_source":str(DEST)}))


if __name__ == "__main__":
    main()
