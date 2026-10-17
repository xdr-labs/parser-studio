#!/usr/bin/env python3
"""Freeze source identity and independent lexical-oracle digests without raw logs.

This is a repository-controlled allowlist, not human semantic verification.
Raw source events and independently tokenized values remain in private state.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


ROOT = Path.home()/".local/state/parserstudio-lossless-fresh-20261017"
OUTPUT = Path(__file__).resolve().parents[2]/"src/poc/sourceTrustPins.json"
UPSTREAM = "ee918d03f4a90dacd32673546c64a633308796ef"
CORPUS = "70fb8f5e9e0753c763c66936880d3ca2b8e590cbadeabf0c8c7a674b7e858039"
SYNTHETIC = '198.51.100.4 id=firewall msg="alpha" msg="beta" action=block'
SYNTHETIC_ID = "synthetic/test-prefix-repeated#1"
SYNTHETIC_FIELDS = [
    ["id", "firewall"], ["msg", "alpha"], ["msg", "beta"], ["action", "block"]
]


def checksum(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_field_hash(fields: list[list[str]]) -> str:
    return checksum(json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode())


def main() -> None:
    frozen = json.loads((ROOT/"manifest.json").read_text())
    if frozen["records_sha256"] != CORPUS or frozen["revision"] != UPSTREAM:
        raise ValueError("Pinned upstream source corpus differs")
    rows = {
        row["id"]: row for row in json.loads((ROOT/"records.json").read_text())
    }
    oracles = json.loads((ROOT/"oracle-prefixed-development.json").read_text())
    if len(oracles) != 8:
        raise ValueError("Expected exactly eight independently tokenized source events")
    entries = []
    for identifier, oracle in sorted(oracles.items()):
        row = rows.get(identifier)
        if not row:
            raise ValueError("Missing pinned original row")
        fields = oracle["fields"]
        prefix = oracle["prefix"]
        if not row["raw"].startswith(prefix):
            raise ValueError("Prefix does not match raw event bytes")
        entries.append({
            "fixtureId": identifier,
            "grammar": "prefixed_kv_space",
            "sourceSha256": checksum(row["raw"].encode()),
            "orderedFieldsSha256": canonical_field_hash(fields),
            "prefixSha256": checksum(prefix.encode()),
            "expectedFieldCount": len(fields),
            "expectedDuplicateCount": len(fields) - len(set(k for k, _ in fields)),
            "oracleStage": "INDEPENDENT_LEXICAL_UNREVIEWED",
        })

    prefix = "198.51.100.4 "
    entries.append({
        "fixtureId": SYNTHETIC_ID,
        "grammar": "prefixed_kv_space",
        "sourceSha256": checksum(SYNTHETIC.encode()),
        "orderedFieldsSha256": canonical_field_hash(SYNTHETIC_FIELDS),
        "prefixSha256": checksum(prefix.encode()),
        "expectedFieldCount": len(SYNTHETIC_FIELDS),
        "expectedDuplicateCount": 1,
        "oracleStage": "SYNTHETIC_CONTROL_ONLY",
    })
    output = {
        "contract": "parser-studio.source-trust-registry.v0.1",
        "upstreamRepository": "https://github.com/elastic/integrations",
        "upstreamRevision": UPSTREAM,
        "recordSetSha256": CORPUS,
        "reviewState": "NOT_HUMAN_REVIEWED",
        "entries": entries,
    }
    encoded = json.dumps(output, indent=2, ensure_ascii=False)+"\n"
    if OUTPUT.exists():
        if OUTPUT.read_text() != encoded:
            raise ValueError("Refusing to overwrite checked-in pinned source-trust registry")
    else:
        OUTPUT.write_text(encoded)
    print(json.dumps({
        "entries": len(entries), "publicIndependentLexical": len(oracles),
        "syntheticControls": 1, "containsRawLogs": False,
        "registrySha256": checksum(encoded.encode()),
    }))


if __name__ == "__main__":
    main()
