"""Strict local-only, SHA-256 pinned public fixture reader.

The source and upstream expected output are NOT redistributed by this repo.
To repeat the experiment, fetch the manifest's exact immutable source URLs
under a separate license review, place bytes in .cache/, and run verification.
This module never opens a network connection.
"""
from pathlib import Path
import hashlib
import json

BASE=Path(__file__).resolve().parent
CACHE=BASE/".cache"
MAX_BYTES=1048576


def entries() -> list[dict]:
    manifest=json.loads((BASE/"manifest.json").read_text("utf8"))
    if manifest.get("contract")!="parser-studio.poc.vendor-corpus.v0.1":
        raise ValueError("MANIFEST_CONTRACT_INVALID")
    fixtures=manifest.get("fixtures")
    if not isinstance(fixtures,list) or len(fixtures)!=8:
        raise ValueError("MANIFEST_FIXTURE_COUNT")
    if len({x["id"] for x in fixtures})!=len(fixtures):
        raise ValueError("MANIFEST_DUPLICATE_ID")
    return fixtures


def load_file(entry:dict,kind:str) -> bytes:
    if kind not in {"raw","gold"}:
        raise ValueError("FIXTURE_KIND_INVALID")
    name=entry["id"]+(".raw" if kind=="raw" else ".gold.json")
    file=CACHE/name
    if not file.is_file():
        raise FileNotFoundError("FIXTURE_LOCAL_CACHE_MISSING:"+name)
    data=file.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    expected=entry["raw_sha256"] if kind=="raw" else entry["gold_sha256"]
    if len(data)>MAX_BYTES or digest!=expected:
        raise ValueError("FIXTURE_SHA256_MISMATCH:"+name)
    return data


def load_case(entry:dict) -> tuple[list[str],list[dict]]:
    raw=load_file(entry,"raw").decode("utf8","strict").splitlines()
    expected=json.loads(load_file(entry,"gold").decode("utf8","strict"))
    if isinstance(expected,dict):
        expected=expected.get("expected")
    if not isinstance(expected,list) or not all(isinstance(x,dict) or x is None for x in expected):
        raise ValueError("FIXTURE_GOLD_INVALID")
    expected=[x if isinstance(x,dict) else {} for x in expected]
    if len(expected)!=len(raw) or len(raw)!=entry["expected_raw_lines"]:
        raise ValueError("FIXTURE_EVENT_ALIGNMENT_INVALID")
    return raw,expected


if __name__=="__main__":
    count=0
    for item in entries():
        raw,gold=load_case(item)
        print(item["id"],"rows",len(raw),"gold",len(gold),"hashes verified")
        count+=len(raw)
    print("PASS",count,"real public upstream log fixture records, local-only, no target egress")
