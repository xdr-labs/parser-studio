#!/usr/bin/env python3
"""Build independent Juniper bare-bracket KV source and malformed-event oracles."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re

KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
UNSAFE = {"__proto__", "constructor", "prototype"}

def parse_attributes(record: str) -> dict[str, str] | None:
    marker = record.find(" [")
    if marker < 0 or not record.endswith("]"):
        return None
    content = record[marker + 2:-1]
    if content.startswith("junos@") or not (
        content.startswith("source-address=") or content.startswith("reason=")
    ):
        return None
    values: dict[str,str] = {}
    pos = 0
    while pos < len(content):
        if pos:
            if content[pos] != " ":
                return None
            pos += 1
        key_match = KEY.match(content, pos)
        if key_match is None:
            return None
        key = key_match.group()
        pos = key_match.end()
        if content[pos:pos+2] != '="':
            return None
        pos += 2
        value = ""
        finished = False
        while pos < len(content):
            ch = content[pos]
            if ch == '"':
                pos += 1
                finished = True
                break
            if ch == "\\":
                if pos + 1 >= len(content) or content[pos + 1] not in ('"', "\\", "]"):
                    return None
                value += content[pos + 1]
                pos += 2
            else:
                if ord(ch) < 32 or ord(ch) == 127:
                    return None
                value += ch
                pos += 1
        if not finished:
            return None
        normalized = key.replace("-", "_")
        if key in UNSAFE or normalized in UNSAFE or normalized in values:
            return None
        values[normalized] = value
        if len(values) > 64:
            return None
    required = ("source_address", "source_port", "destination_address", "destination_port")
    if any(not values.get(key) for key in required):
        return None
    try:
        ipaddress.ip_address(values["source_address"])
        ipaddress.ip_address(values["destination_address"])
        src_port = int(values["source_port"])
        dst_port = int(values["destination_port"])
        if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
            return None
    except ValueError:
        return None
    return values

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir",type=Path,
        default=Path.home()/".local/state/parserstudio-fresh-vendor-holdout-20261016")
    args = parser.parse_args()
    private = args.input_dir.expanduser().resolve()
    rows = json.loads((private/"records.json").read_text(encoding="utf-8"))
    juniper = [row for row in rows if row["source"].startswith("juniper_srx/log/")]
    oracle: dict[str,dict[str,str]] = {}
    negatives: list[dict[str,str]] = []
    for row in juniper:
        raw = row["raw"]
        fields = parse_attributes(raw)
        if fields is None:
            continue
        oracle[row["id"]] = fields
        first = "[source-address=" if "[source-address=" in raw else " source-address="
        variants = {
            "calendar":re.sub(r"\d{4}-\d{2}-\d{2}(?=T)","2026-02-30",raw,count=1),
            "priority":re.sub(r"^<\d{1,3}>","<192>",raw,count=1),
            "duplicate":raw[:-1]+' source-address="192.0.2.10"]',
            "unsafe":raw[:-1]+' constructor="bad"]',
            "truncated":raw[:-1],
            "unclosed":raw[:-1]+' unfinished="bad]',
            "invalid-ip":re.sub(r'source-address="[^"]*"','source-address="999.999.999.999"',raw,count=1),
            "invalid-port":re.sub(r'destination-port="[^"]*"','destination-port="70000"',raw,count=1),
            "wrong-app":raw.replace(" RT_FLOW - "," NOT_VENDOR - ",1),
        }
        for kind, changed in variants.items():
            if changed != raw:
                negatives.append({"id":row["id"]+"/"+kind,"source":row["source"],"raw":changed})
    assert len(oracle) == 5, f"Expected five independently parsable bare bracket records, got {len(oracle)}"
    assert len(negatives) == 45, f"Unexpected number of negative events: {len(negatives)}"
    for file, value in [
        ("junos_bare_oracle.json",oracle),
        ("junos_bare_mutations.json",negatives),
    ]:
        p = private/file
        p.write_text(json.dumps(value,ensure_ascii=False),encoding="utf-8")
        os.chmod(p,0o600)
    print(json.dumps({"events":len(juniper),"bare_bracket_oracles":len(oracle),
        "invalid_variants":len(negatives)}))

if __name__ == "__main__":
    main()
