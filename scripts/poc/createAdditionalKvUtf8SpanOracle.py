#!/usr/bin/env python3
"""New UTF-8 span-only audit of independently frozen Fortinet, SonicWall, Sophos originals.

Reuses the independent byte scanner from this PoC, not the TypeScript candidate.
Source fields/values are pinned from earlier separate source-oracle producers.
Neither this script nor its result is manufacturer-certified.
"""
from __future__ import annotations
import importlib.util
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

ROOT = Path.home() / ".local/state"
OUTPUT = ROOT / "parserstudio-source-kv-byte-span-20261017"
MODULE = Path(__file__).with_name("createSourceKvUtf8SpanOracle.py")
_spec = importlib.util.spec_from_file_location("source_byte_oracle", MODULE)
engine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(engine)
SOURCE_FILES = {
    "fortinet_fg": ("parserstudio-fresh-kv-20261017/fg.log",
                    "e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2"),
    "fortinet_fg_long": ("parserstudio-fresh-kv-20261017/fg_long.log",
                         "53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440"),
    "sonicwall_orig": ("parserstudio-fresh-sonicwall-20261017/sonicwall.log.orig",
                       "949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9"),
    "sophos_records": ("parserstudio-fresh-vendor-holdout-20261016/records.json",
                       "3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2"),
}
REFERENCE_FILES = {
    "fortinet": ("parserstudio-fresh-kv-20261017/oracle-fresh-bare-kv-fields.json",
                 "cdcf58126d8c45eb96b6832c381b6d943d07cde78ea2ee39648c402207a97fc9"),
    "sonicwall": ("parserstudio-fresh-sonicwall-20261017/oracle-fresh-sonicwall-syslog-kv.json",
                  "a3204563622c538a870d6e5cbe9756d01c86a6edfe87eafef16c6d9ed8be038a"),
    "sophos": ("parserstudio-fresh-vendor-holdout-20261016/sophos_kv_oracle.json",
               "b1ebbc634268050a276fe3af1e478652cfdb71a88b4e0c2d14cae5114210f3fb"),
}


def pinned(relative: str, sha256: str) -> bytes:
    raw = (ROOT / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise AssertionError("Pinned independent source file or expected oracle changed")
    return raw


def main() -> None:
    os.umask(0o077)
    sources = {kind: pinned(*record) for kind, record in SOURCE_FILES.items()}
    ref = {kind: json.loads(pinned(*record)) for kind, record in REFERENCE_FILES.items()}
    if len(ref["fortinet"]) != 1002 or len(ref["sonicwall"]["accepted"]) != 59:
        raise ValueError("Frozen Fortinet/SonicWall original count changed")
    if len(ref["sonicwall"]["unscorableSourceSha256"]) != 2:
        raise ValueError("Known unscorable SonicWall originals disappeared")
    if len(ref["sophos"]["oracle"]) != 151 or len(ref["sophos"]["unscannable"]) != 120:
        raise ValueError("Frozen Sophos source oracle changed")
    written: dict[str, object] = {}
    stats: dict[str, Counter] = {x: Counter() for x in ("fortinet", "sonicwall", "sophos")}
    seen: set[str] = set()

    def include(raw: str, family: str, fields: list, expected_sha: str) -> None:
        raw_bytes = raw.encode("utf-8")
        sha = engine.digest(raw_bytes)
        if sha != expected_sha or sha in seen:
            raise ValueError("Original source identity conflict or source overlap")
        seen.add(sha)
        spans = engine.scan_source(raw_bytes)
        if spans is None or len(spans["fields"]) != len(fields):
            written[sha] = {"sourceSha256": sha, "status": "SOURCE_UNSCORABLE"}
            stats[family]["unscorable"] += 1
            return
        mismatch = 0
        for field, (name, val) in zip(spans["fields"], fields):
            if field["name"] != name:
                mismatch += 1
            field["referenceValue"] = val
            field["referenceStatus"] = ("SOURCE_QUALIFIED" if
                                       field["name"] == name and field["value"] == val
                                       else "VALUE_AMBIGUOUS")
            mismatch += int(field["value"] != val)
        written[sha] = {
            "sourceSha256": sha, "sourceBytes": len(raw_bytes),
            "status": "SOURCE_PARTIAL" if mismatch else "SOURCE_QUALIFIED",
            "envelope": spans["envelope"], "family": family, "fields": spans["fields"],
        }
        stats[family]["fields"] += len(fields)
        stats[family]["events"] += 1
        stats[family]["conflicts"] += mismatch
        stats[family]["exactEvents"] += mismatch == 0

    physical, duplicates = 0, 0
    for label in ("fortinet_fg", "fortinet_fg_long"):
        for raw in sources[label].decode("utf-8").splitlines():
            if not raw.strip():
                continue
            physical += 1
            sha = engine.digest(raw.encode("utf-8"))
            if sha in seen:
                duplicates += 1
                continue
            reference = ref["fortinet"].get(sha)
            if reference is None:
                raise ValueError("Fresh Fortinet source has no pinned original value oracle")
            include(raw, "fortinet", reference["fields"], reference["sha256"])
    if physical != 1008 or duplicates != 6:
        raise AssertionError("Fresh physical Fortinet denominator changed")

    for raw in sources["sonicwall_orig"].decode("utf-8").splitlines():
        if not raw.strip():
            continue
        sha = engine.digest(raw.encode("utf-8"))
        expected = ref["sonicwall"]["accepted"].get(sha)
        if expected is not None:
            include(raw, "sonicwall", expected["fields"], expected["sha256"])
        elif sha in ref["sonicwall"]["unscorableSourceSha256"]:
            if sha in seen:
                raise ValueError("SonicWall unscorable original duplicated")
            seen.add(sha)
            written[sha] = {"sourceSha256": sha, "status": "SOURCE_UNSCORABLE"}
            stats["sonicwall"]["unscorable"] += 1
        else:
            raise ValueError("SonicWall source missing from independently pinned reference")

    rows = json.loads(sources["sophos_records"])
    sourceSophos = [item for item in rows if item["source"].startswith("sophos/xg/")]
    if len(rows) != 571 or len(sourceSophos) != 271:
        raise AssertionError("Frozen Sophos source records changed")
    for row in sourceSophos:
        expected = ref["sophos"]["oracle"].get(row["id"])
        if expected is not None:
            include(row["raw"], "sophos", list(expected.items()),
                    engine.digest(row["raw"].encode("utf-8")))
        else:
            stats["sophos"]["unscoredOriginals"] += 1

    if stats["fortinet"]["events"] != 1002 or stats["sonicwall"]["events"] != 59 or (
        stats["sophos"]["events"] != 151):
        raise AssertionError("New span reference qualified denominators drift")
    if (stats["fortinet"]["fields"], stats["sonicwall"]["fields"],
        stats["sophos"]["fields"]) != (11848, 759, 4956):
        raise AssertionError("Previously pinned original field denominators drift")

    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = OUTPUT / "additional-source-kv-utf8-byte-spans.json"
    doc = {"schemaVersion": 1, "references": {key: sha for key, (_, sha) in REFERENCE_FILES.items()},
           "records": written, "sourceStats": {name: dict(x) for name, x in stats.items()},
           "manufacturerSemantics": "NOT_CERTIFIED", "nativeParser": "NOT_VERIFIED"}
    blob = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if target.exists():
        if target.read_bytes() != blob:
            raise ValueError("Refusing to overwrite existing frozen additional Oracle")
    else:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
    if target.stat().st_mode & 0o077:
        raise PermissionError("Private additional span oracle mode is not 0600")
    print("ADDITIONAL_INDEPENDENT_BYTE_SPAN_ORACLES " + json.dumps({
        "byCohort": {key: dict(x) for key, x in stats.items()},
        "byteSpanOracleSha256": engine.digest(blob), "originalRowsStoredPrivate": len(written),
        "rawValuesPrinted": False, "semantics": "NOT_CERTIFIED",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
