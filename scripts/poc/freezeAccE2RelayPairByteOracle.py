#!/usr/bin/env python3
"""Freeze authored generic source/collector byte pairs, independently of the TypeScript candidate.

These are synthetic structural checks. They are NOT producer-attested device wire.
"""
import hashlib
import json
from pathlib import Path

base = Path(__file__).resolve().parent
pairs = [
    ("unchanged_ascii", b"<134>1 2026-10-18T00:00:00Z src app - - - body=ok",
     b"<134>1 2026-10-18T00:00:00Z src app - - - body=ok", "REVIEW_ONLY_EQUAL_BYTES"),
    ("unchanged_utf8", "field=😀 msg=ok".encode("utf-8"),
     "field=😀 msg=ok".encode("utf-8"), "REVIEW_ONLY_EQUAL_BYTES"),
    ("truncated_ascii", b"prefix-field=" + b"x" * 60, b"prefix-field=" + b"x" * 23,
     "REVIEW_ONLY_COLLECTOR_STRICT_PREFIX"),
    ("truncated_multibyte", "field=😀 tail=done".encode("utf-8"),
     "field=😀 tail=done".encode("utf-8")[:8], "REVIEW_ONLY_COLLECTOR_STRICT_PREFIX"),
    ("trailing_space", b"event=1 done=true", b"event=1 done=true ",
     "REVIEW_ONLY_COLLECTOR_APPEND_ONLY"),
    ("trailing_tag", b"event=2 done=true", b"event=2 done=true relay=sec",
     "REVIEW_ONLY_COLLECTOR_APPEND_ONLY"),
    ("interior_replacement", b"abc123xyz", b"abc456xyz",
     "REVIEW_ONLY_NON_PREFIX_CHANGE"),
    ("first_byte_replacement", b"abc123", b"Zbc123",
     "REVIEW_ONLY_NON_PREFIX_CHANGE"),
    ("shortened_with_replacement", b"abc123XYZ", b"abc000",
     "REVIEW_ONLY_NON_PREFIX_CHANGE"),
    ("extended_with_replacement", b"abc123XYZ", b"abc000XYZextra",
     "REVIEW_ONLY_NON_PREFIX_CHANGE"),
    ("opaque_equal_binary", bytes([0x00, 0xff, 0x80, 0x1f]),
     bytes([0x00, 0xff, 0x80, 0x1f]), "REVIEW_ONLY_EQUAL_BYTES"),
    ("opaque_binary_prefix", bytes([0xf0, 0x9f, 0x92, 0xa9, 0xff]),
     bytes([0xf0, 0x9f, 0x92]), "REVIEW_ONLY_COLLECTOR_STRICT_PREFIX"),
]
rows = []
for name, upstream, collector, disposition in pairs:
    cp = 0
    while cp < min(len(upstream), len(collector)) and upstream[cp] == collector[cp]:
        cp += 1
    rows.append({
        "id": name, "upstreamHex": upstream.hex(), "collectorHex": collector.hex(),
        "upstreamSha256": hashlib.sha256(upstream).hexdigest(),
        "collectorSha256": hashlib.sha256(collector).hexdigest(),
        "expectedDisposition": disposition,
        "expectedCommonPrefixBytes": cp,
        "expectedFirstDifferenceByte": None if upstream == collector else cp,
        "expectedLostUpstreamTail": [len(collector), len(upstream)]
        if disposition == "REVIEW_ONLY_COLLECTOR_STRICT_PREFIX" else None,
        "expectedAddedCollectorTail": [len(upstream), len(collector)]
        if disposition == "REVIEW_ONLY_COLLECTOR_APPEND_ONLY" else None,
    })
out = {
    "provenance": "INDEPENDENT_STANDARDS_AUTHORED_SYNTHETIC_NOT_DEVICE",
    "frozenBeforeCandidateImplementation": True,
    "pairs": rows,
}
path = base / "accE2RelayPairByteOracle.pinned.json"
data = (json.dumps(out, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
path.write_bytes(data)
print("Oracle frozen", path.name, "cases=", len(rows), "sha256=", hashlib.sha256(data).hexdigest())
