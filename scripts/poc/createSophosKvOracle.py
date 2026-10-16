#!/usr/bin/env python3
"""Independently tokenize pinned Sophos XG source KV events into private field-value oracles."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}=")
SOURCE = re.compile(r"^<\d{1,3}>")
UNSAFE = {"__proto__", "constructor", "prototype"}

def parse_fields(raw: str) -> dict[str,str] | None:
    text = SOURCE.sub("", raw, count=1)
    if not text or "\x00" in text or "\r" in text or "\n" in text or len(text.encode()) > 16384:
        return None
    values: dict[str,str] = {}
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t":
            pos += 1
        if pos == len(text):
            break
        match = NAME.match(text, pos)
        if not match:
            return None
        name = match.group()[:-1]
        if name in values or name in UNSAFE:
            return None
        pos = match.end()
        value = ""
        if pos < len(text) and text[pos] in "\"'":
            quote = text[pos]
            pos += 1
            closed = False
            while pos < len(text):
                char = text[pos]
                if char == "\\":
                    if pos + 1 >= len(text):
                        return None
                    value += text[pos + 1]
                    pos += 2
                elif char == quote:
                    pos += 1
                    closed = True
                    break
                else:
                    value += char
                    pos += 1
            if not closed:
                return None
        else:
            while pos < len(text) and text[pos] not in " \t":
                char = text[pos]
                if char in "\"'":
                    return None
                if char == "\\":
                    if pos + 1 >= len(text):
                        return None
                    value += text[pos + 1]
                    pos += 2
                else:
                    value += char
                    pos += 1
        if pos < len(text) and text[pos] not in " \t":
            return None
        if len(value.encode()) > 8192 or len(values) >= 256:
            return None
        values[name] = value
    return values or None

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path,default=Path.home()/".local/state/parserstudio-fresh-vendor-holdout-20261016")
    args = p.parse_args()
    root = args.input_dir.expanduser().resolve()
    records = json.loads((root/"records.json").read_text(encoding="utf-8"))
    sophos = [row for row in records if row["source"].startswith("sophos/xg/")]
    oracle = {}
    invalid = []
    for row in sophos:
        fields = parse_fields(row["raw"])
        if fields is None:
            invalid.append(row["id"])
        else:
            oracle[row["id"]] = fields
    assert len(sophos) == 271
    output=root/"sophos_kv_oracle.json"
    output.write_text(json.dumps({"oracle":oracle,"unscannable":invalid},ensure_ascii=False),encoding="utf-8")
    os.chmod(output,0o600)
    mutations = []
    for row in sophos:
        if row["id"] not in oracle or oracle[row["id"]].get("device") != "SFW":
            continue
        raw = row["raw"]
        changes = {
            "invalid-calendar": re.sub(r"\bdate=\d{4}-\d{2}-\d{2}", "date=2026-02-30", raw, count=1),
            "wrong-source": raw.replace('device="SFW"', 'device="UNRECOGNIZED"', 1),
            "duplicate-anchor": raw + ' device_name="duplicate"',
            "unterminated-quote": raw + ' unclosed="',
            "invalid-ip": re.sub(r"\bsrc_ip=(?:\"[^\"]*\"|[^ \t]*)", "src_ip=999.999.999.999", raw, count=1),
            "invalid-port": re.sub(r"\bdst_port=(?:\"[^\"]*\"|[^ \t]*)", "dst_port=70000", raw, count=1),
        }
        if changes["invalid-ip"] == raw:
            changes["invalid-ip"] = raw + " src_ip=999.999.999.999"
        if changes["invalid-port"] == raw:
            changes["invalid-port"] = raw + " dst_port=70000"
        for category,variant in changes.items():
            if variant != raw:
                mutations.append({"id":row["id"] + "/" + category,"raw":variant})
    assert len(mutations) == 900, "Unexpected source-qualified mutation count"
    mutations_file = root/"sophos_kv_mutations.json"
    mutations_file.write_text(json.dumps(mutations,ensure_ascii=False),encoding="utf-8")
    os.chmod(mutations_file,0o600)
    print(json.dumps({"sophos_events":len(sophos),"scanned_oracles":len(oracle),
        "unsafe_or_ambiguous":len(invalid),"mutation_count":len(mutations),
        "unscannable_ids":invalid[:12]}))

if __name__ == "__main__":
    main()
