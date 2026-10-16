#!/usr/bin/env python3
"""Build private independent field-value oracles for the pinned Junos bracket holdout."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

SD_ID = re.compile(r"junos@[A-Za-z0-9.:-]{1,64}")
KV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
UNSAFE = {"__proto__", "constructor", "prototype"}

def extract_junos_fields(source: str) -> dict[str, str] | None:
    marker = source.find("[junos@")
    if marker < 0 or not source.endswith("]") or source.count("[junos@") != 1:
        return None
    fragment = source[marker+1:-1]
    header = SD_ID.match(fragment)
    if header is None:
        return None
    result: dict[str, str] = {}
    position = header.end()
    while position < len(fragment):
        if fragment[position] != " ":
            return None
        position += 1
        key_match = KV_KEY.match(fragment, position)
        if key_match is None:
            return None
        key = key_match.group()
        position = key_match.end()
        if fragment[position:position+2] != '="':
            return None
        position += 2
        value = ""
        complete = False
        while position < len(fragment):
            char = fragment[position]
            if char == '"':
                complete = True
                position += 1
                break
            if char == "\\":
                if position + 1 >= len(fragment):
                    return None
                escaped = fragment[position + 1]
                if escaped not in ('"', "\\", "]"):
                    return None
                value += escaped
                position += 2
                continue
            if ord(char) < 32 or ord(char) == 127:
                return None
            value += char
            position += 1
        if not complete:
            return None
        safe_key = key.replace("-", "_")
        if key in UNSAFE or safe_key in UNSAFE or safe_key in result:
            return None
        result[safe_key] = value
        if len(result) > 64:
            return None
    return result or None

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path,
        default=Path.home() / ".local/state/parserstudio-fresh-vendor-holdout-20261016")
    args = parser.parse_args()
    private_dir = args.input_dir.expanduser().resolve()
    records = json.loads((private_dir/"records.json").read_text(encoding="utf-8"))
    juniper = [r for r in records if r["source"].startswith("juniper_srx/log/")]
    oracle = {}
    rejected = []
    for row in juniper:
        fields = extract_junos_fields(row["raw"])
        if fields is not None:
            oracle[row["id"]] = fields
        else:
            rejected.append(row["id"])
    assert len(juniper) == 105
    oracle_path = private_dir / "junos_bracket_oracle.json"
    oracle_path.write_text(json.dumps({"oracle":oracle,"unscannable":rejected},
        ensure_ascii=False),encoding="utf-8")
    os.chmod(oracle_path,0o600)
    negatives: list[dict[str,str]] = []
    first_attr = re.compile(r' ([A-Za-z_][A-Za-z0-9_-]{0,63})="')
    for row in juniper:
        if row["id"] not in oracle:
            continue
        raw = row["raw"]
        match = first_attr.search(raw[raw.index("[junos@"):])
        if match is None:
            continue
        attr_name = match.group(1)
        mutations = {
            "bad-calendar": re.sub(r"\d{4}-\d{2}-\d{2}(?=T)", "2026-02-30", raw, count=1),
            "bad-priority": re.sub(r"^<\d{1,3}>", "<192>", raw, count=1),
            "duplicate-attribute": raw[:-1] + f' {attr_name}="conflict"]',
            "unsafe-attribute": raw[:-1] + ' constructor="evil"]',
            "unclosed-quote": raw[:-1] + ' unfinished="broken]',
            "truncated-data": raw[:-1],
        }
        for kind,mutation in mutations.items():
            if mutation != raw:
                negatives.append({"id":row["id"] + "/" + kind, "raw":mutation})
    mutation_path = private_dir / "junos_bracket_mutations.json"
    mutation_path.write_text(json.dumps(negatives, ensure_ascii=False), encoding="utf-8")
    os.chmod(mutation_path,0o600)
    print(json.dumps({"juniper_events":len(juniper),"junos_bracket_oracles":len(oracle),
        "not_independently_scannable":len(rejected),"malformed_variants":len(negatives)}))

if __name__=="__main__":
    main()
