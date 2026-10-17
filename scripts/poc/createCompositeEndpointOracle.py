#!/usr/bin/env python3
"""Independently type-tokenize complete original source endpoints in PRIVATE state.

This Python oracle does not trust or import the TypeScript composite lexer.
It is a lexical / type oracle only, not a vendor semantic mapping approval.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

ROOT = Path.home()/".local/state/parserstudio-lossless-fresh-20261017"
EXPECTED = "70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039"
INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\/-]{0,31}$")
LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def parse_endpoint(raw: str) -> list[list[str]] | None:
    if not raw or len(raw) > 512 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        return None
    tokens = raw.split(":")
    if len(tokens) not in (3, 4):
        return None
    try:
        v4 = ipaddress.IPv4Address(tokens[0])
        if str(v4) != tokens[0]:
            return None
        port = int(tokens[1])
    except (ValueError, ipaddress.AddressValueError):
        return None
    if str(port) != tokens[1] or not 0 <= port <= 65535 or not INTERFACE.fullmatch(tokens[2]):
        return None
    result = [["ipv4", tokens[0]], ["port", tokens[1]], ["interface", tokens[2]]]
    if len(tokens) == 4:
        name = tokens[3]
        if len(name) > 253 or not name or len(name.split(".")) > 64 or not all(
            LABEL.fullmatch(part) for part in name.split(".")
        ):
            return None
        result.append(["resolvedHost", name])
    return result


def main() -> None:
    pinned = json.loads((ROOT/"manifest.json").read_text())
    if pinned["records_sha256"] != EXPECTED:
        raise ValueError("Source corpus identity drifted")
    sources = json.loads((ROOT/"records.json").read_text())
    by_id = {row["id"]: row for row in sources}
    fixture_refs = json.loads((ROOT/"oracle-prefixed-development.json").read_text())
    if len(fixture_refs) != 8:
        raise ValueError("Pinned lexical oracle must contain eight events")
    reference = {}
    for identifier, source in sorted(fixture_refs.items()):
        row = by_id.get(identifier)
        if not row:
            raise ValueError("Pinned original event missing")
        attributes = source["fields"]
        fields = dict(attributes)
        for key in ("src", "dst"):
            parsed = parse_endpoint(fields[key]) if key in fields else None
            if parsed is None:
                raise ValueError("Independent endpoint grammar cannot certify an original field")
            reference[f"{identifier}/{key}"] = {
                "eventId": identifier,
                "field": key,
                "sourceSha256": hashlib.sha256(row["raw"].encode()).hexdigest(),
                "parts": parsed,
            }
    destination = ROOT/"oracle-composite-endpoint.json"
    encoded = json.dumps(reference, sort_keys=True, ensure_ascii=False)
    if destination.exists():
        if destination.read_text() != encoded:
            raise ValueError("Refusing to overwrite pinned private independent oracle")
    else:
        destination.write_text(encoded)
        os.chmod(destination, 0o600)
    print(json.dumps({"sourceEvents": len(fixture_refs),
        "componentOracles": len(reference), "all_private": True}))


if __name__ == "__main__":
    main()
