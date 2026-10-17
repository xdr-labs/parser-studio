#!/usr/bin/env python3
"""Freeze new publisher source/evidence pairs before implementing a candidate.

Cisco provides header field names/order. Elastic publisher provides expected
normalized values; this evaluator computes source offsets, NOT the publisher.
Private originals and expected outputs are never checked into Git.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import urllib.request

UPSTREAM = "615252c0910be1b8dc4dbe8f70acabe02ea8757e"
STEMS = (
    "test-pipeline-ad-connector",
    "test-pipeline-cise-alarm",
    "test-pipeline-guest",
    "test-pipeline-policy-diagnostics",
    "test-pipeline-system-statistics",
    "test-pipeline-tacacs-accounting",
)
SUBDIR = "packages/cisco_ise/data_stream/log/_dev/test/pipeline"
PRIVATE = Path.home() / ".local/state/parserstudio-declared-syslog-publisher-20261017"
MANIFEST = Path(__file__).resolve().parent / "declaredSyslogPublisherManifest.pinned.json"
AUTHORITATIVE_CONTRACT = (
    "https://www.cisco.com/c/en/us/td/docs/security/ise/syslog/"
    "Cisco_ISE_Syslogs/m_IntrotoSyslogs.html"
)
FIELDS = (
    ("pri", ("log", "syslog", "priority")),
    ("hostname", ("host", "hostname")),
    ("cat_name", ("cisco_ise", "log", "category", "name")),
    ("msg_id", ("cisco_ise", "log", "message", "id")),
    ("total_seg", ("cisco_ise", "log", "segment", "total")),
    ("seg_num", ("cisco_ise", "log", "segment", "number")),
)
# This independent locator follows Cisco's *declared* ordered header, not
# any parser candidate output. Unknown or mismatched fields remain UNSCORABLE.
HEADER = re.compile(
    r"^<(?P<pri>[0-9]{1,3})>"
    r"[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2} +"
    r"(?P<hostname>[^ \r\n]+) +(?P<cat_name>[^ \r\n]+) +"
    r"(?P<msg_id>[0-9]{1,10}) +(?P<total_seg>[0-9]{1,4}) +"
    r"(?P<seg_num>[0-9]{1,4})(?: +|$)"
)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "ParserStudio-ProvenanceAudit"})
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read()
    if len(data) > 2_000_000:
        raise ValueError("Upstream fixture exceeded evaluation bound")
    return data

def retain(name, data):
    dest = PRIVATE / name
    if dest.exists():
        if dest.read_bytes() != data:
            raise ValueError("Already frozen private fixture drift: " + name)
        return
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)

def nested(obj, path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj

def evaluate_original(raw, expected):
    if nested(expected, ("event", "original")) != raw:
        return [], "UNSCORABLE_PUBLISHER_ORIGINAL_NOT_ALIGNED"
    hit = HEADER.match(raw)
    if not hit:
        return [], "UNSCORABLE_DECLARED_HEADER_NOT_QUALIFIED"
    pri = int(hit["pri"])
    msgid = int(hit["msg_id"])
    total = int(hit["total_seg"])
    seg = int(hit["seg_num"])
    if pri > 191 or not (1 <= msgid <= 4294967295) or not (1 <= total <= 1000) or not (0 <= seg <= total):
        return [], "UNSCORABLE_SOURCE_HEADER_BOUNDS"
    fields = []
    for name, normalized_path in FIELDS:
        original = hit[name]
        external = nested(expected, normalized_path)
        if external is None or isinstance(external, (dict, list, bool)):
            continue
        # Publisher normalizes numeric values; only assert their typed equality
        # while retaining the exact raw lexeme as the source field value.
        match = (str(external) == original)
        if name in ("pri", "total_seg", "seg_num"):
            match = match or (str(external) == str(int(original)))
        if not match:
            continue
        start, end = hit.span(name)
        a = len(raw[:start].encode("utf-8"))
        b = len(raw[:end].encode("utf-8"))
        if raw.encode("utf-8")[a:b].decode("utf-8") != original:
            raise ValueError("Independent UTF-8 field span replay failed")
        fields.append({
            "name": name,
            "value": original,
            "startByte": a,
            "endByte": b,
            "publisherExpectedPath": ".".join(normalized_path),
            "sourceFieldNameAuthor": "CISCO_OFFICIAL_DOCUMENTATION",
            "sourceSpanAuthor": "INDEPENDENT_EVALUATOR_BEFORE_CANDIDATE",
        })
    return fields, "PARTIAL_SCORE" if fields else "UNSCORABLE_NO_ALIGNED_AUTHOR_FIELDS"

def main():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    license_bytes = get(f"https://raw.githubusercontent.com/elastic/integrations/{UPSTREAM}/LICENSE.txt")
    if b"Elastic License" not in license_bytes:
        raise ValueError("Publisher license unexpected")
    retain("LICENSE.txt", license_bytes)
    manifest = {
        "publisher": "elastic/integrations", "publisherRevision": UPSTREAM,
        "manufacturerFieldOrderSource": AUTHORITATIVE_CONTRACT,
        "sourceSchema": ["pri", "timestamp", "hostname", "cat_name",
                         "msg_id", "total_seg", "seg_num", "payload"],
        "publisherLicense": "Elastic License 2.0, private evaluation only",
        "licenseSha256": sha(license_bytes),
        "originalOrExpectedDataCommitted": False,
        "completeEventOracle": False,
        "publisherProvidedExactByteOffsets": False,
        "files": [],
    }
    rows = []
    for stem in STEMS:
        pair = []
        for suffix in (".log", ".log-expected.json"):
            remote = f"{SUBDIR}/{stem}{suffix}"
            data = get(f"https://raw.githubusercontent.com/elastic/integrations/{UPSTREAM}/{remote}")
            retain(stem + suffix, data)
            manifest["files"].append({"upstreamPath": remote, "sha256": sha(data),
                                      "bytes": len(data)})
            pair.append(data)
        originals = pair[0].decode("utf-8").splitlines()
        author = json.loads(pair[1].decode("utf-8"))["expected"]
        if len(originals) != len(author):
            raise ValueError("Source/expected cardinality differs: " + stem)
        for number, (raw, expectation) in enumerate(zip(originals, author), 1):
            fields, status = evaluate_original(raw, expectation)
            rows.append({
                "sourceFile": stem + ".log", "line": number, "raw": raw,
                "rawSha256": sha(raw.encode("utf-8")), "status": status, "fields": fields,
                "manufacturerEscapeMeaning": "UNSCORABLE",
                "emptyAbsentNilSemantics": "UNSCORABLE",
                "nativeStellar": "NOT_VERIFIED",
            })
    blob = json.dumps(rows, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    retain("declared-cisco-source-oracle.v1.json", blob)
    summary = {
        "allPublisherLines": len(rows),
        "partialScorable": sum(bool(r["fields"]) for r in rows),
        "unscorable": sum(not r["fields"] for r in rows),
        "expectedSourceTuples": sum(len(r["fields"]) for r in rows),
        "withEscapesButUnqualified": sum("\\" in r["raw"] for r in rows),
        "withSyntacticEmptiesButUnqualified": sum(
            ('=""' in r["raw"] or "=, " in r["raw"] or ",," in r["raw"]) for r in rows),
    }
    manifest["oracle"] = {"privateFile": "declared-cisco-source-oracle.v1.json",
                          "sha256": sha(blob), "counts": summary,
                          "caveat": "field names manufacturer documented; expected values publisher ECS; byte offsets evaluator-generated"}
    output = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if MANIFEST.exists():
        if MANIFEST.read_bytes() != output:
            raise ValueError("Previously committed public provenance manifest drifted")
    else:
        MANIFEST.write_bytes(output)
    print(json.dumps({
        "status": "ORACLE_FROZEN_BEFORE_CANDIDATE",
        "originalOrExpectedValuesPrinted": False,
        "oracleSha256": sha(blob), "counts": summary,
        "sources": len(STEMS), "sourcePairs": len(manifest["files"]) // 2,
        "manufacturerExactByteOracle": False,
    }, sort_keys=True))

if __name__ == "__main__":
    main()
