#!/usr/bin/env python3
"""Independent Python source field oracle for *pre-frozen* unreviewed JSON logs.

Exact original JSON leaf paths and values are stored only in restricted local
state. This is source-field fidelity, NOT semantic Stellar normalization.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path

ROOT = Path.home()/".local/state/parserstudio-lossless-blind-20261017"
FROZEN = "153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32"
DANGEROUS = {"__proto__", "constructor", "prototype"}
MAX_LEAVES = 4096
MAX_DEPTH = 24


def field_map(value: object) -> dict[str, object]:
    output: dict[str, object] = {}

    def recurse(part: object, pointer: str, depth: int) -> None:
        if depth > MAX_DEPTH or len(output) > MAX_LEAVES:
            raise ValueError("JSON source is outside bounded independent oracle")
        if isinstance(part, dict):
            for key, child in part.items():
                if key in DANGEROUS or len(key) > 256:
                    raise ValueError("Unsafe JSON source key")
                escaped = key.replace("~", "~0").replace("/", "~1")
                recurse(child, pointer+"/"+escaped, depth+1)
        elif isinstance(part, list):
            for index, child in enumerate(part):
                recurse(child, pointer+"/"+str(index), depth+1)
        else:
            if isinstance(part, int) and not isinstance(part, bool) and abs(part)>2**53-1:
                raise ValueError("Unscoreable JSON numeric precision")
            if isinstance(part, float) and not math.isfinite(part):
                raise ValueError("Unscoreable non-finite source value")
            output[pointer] = part

    recurse(value, "", 0)
    if not output or len(output)>MAX_LEAVES:
        raise ValueError("Zero or excessive original JSON leaf fields")
    return output


def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Repeated JSON source member cannot be silently collapsed")
        result[name] = value
    return result


def bad_constant(value: str) -> object:
    raise ValueError(f"Forbidden JSON constant {value}")


def main() -> None:
    manifest=json.loads((ROOT/"manifest.json").read_text())
    records=(ROOT/"records.json").read_bytes()
    assert hashlib.sha256(records).hexdigest() == FROZEN
    assert manifest["record_sha256"] == FROZEN
    events=json.loads(records)
    assert len(events)==222
    field_sources: dict[str, dict[str, object]]={}
    families: dict[str, int]={}
    for row in events:
        raw=row["raw"]
        try:
            source=json.loads(raw, object_pairs_hook=reject_duplicate,
                parse_constant=bad_constant)
        except json.JSONDecodeError:
            continue
        if not isinstance(source,dict):
            continue
        expected=field_map(source)
        field_sources[row["id"]]={
            "sourceSha256":hashlib.sha256(raw.encode()).hexdigest(),
            "fields":expected,
            "family":row["source"].split("/")[1],
        }
        vendor=row["source"].split("/")[1]
        families[vendor]=families.get(vendor,0)+1
    if len(field_sources)!=22:
        raise ValueError(f"Expected 22 published JSON documents, got {len(field_sources)}")
    data=json.dumps(field_sources,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    output=ROOT/"oracle-blind-json-fields.json"
    if output.exists():
        if output.read_text()!=data:
            raise ValueError("Refusing to alter frozen independently parsed source oracle")
    else:
        output.write_text(data)
        os.chmod(output,0o600)
    print(json.dumps({
        "sourceEvents":len(events),"jsonDocuments":len(field_sources),
        "jsonLeafFields":sum(len(v["fields"]) for v in field_sources.values()),
        "byVendor":families,"sourceValuesRemainPrivate":True,
    }))


if __name__=="__main__":
    main()
