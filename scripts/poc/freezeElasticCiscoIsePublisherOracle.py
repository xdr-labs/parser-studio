#!/usr/bin/env python3
"""Freeze independent publisher-authored source assertions before candidate scoring.

All upstream raw events and expected values stay in private 0700/0600 state.
Elasticsearch/ECS fields are publisher assertions, not device-semantic truth.
"""
import hashlib
import json
import os
import re
import urllib.request
from pathlib import Path

REVISION = "615252c0910be1b8dc4dbe8f70acabe02ea8757e"
REPOSITORY = "elastic/integrations"
PATH = "packages/cisco_ise/data_stream/log/_dev/test/pipeline"
STEMS = (
    "test-pipeline-failed-attempts",
    "test-pipeline-passed-authentications",
    "test-pipeline-administrative-and-operational-audit",
    "test-pipeline-radius-diagnostics",
)
BASE = f"https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/"
PRIVATE = Path.home() / ".local/state/parserstudio-elastic-cisco-ise-independent-20261017"
PUBLIC = Path(__file__).resolve().parent / "elasticCiscoIseSourceManifest.pinned.json"
SOURCE_MAP = (
    ("pri", ("log", "syslog", "priority")),
    ("hostname", ("host", "hostname")),
    ("appname", ("cisco_ise", "log", "category", "name")),
    ("message_id", ("cisco_ise", "log", "message", "id")),
)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def download(name):
    url = BASE + name
    req = urllib.request.Request(url, headers={"User-Agent": "ParserStudio-SourceAudit"})
    with urllib.request.urlopen(req, timeout=25) as response:
        data = response.read()
    if len(data) > 2_000_000:
        raise ValueError("Oversized upstream fixture")
    return data

def private_write(file, data):
    if file.exists():
        if sha(file.read_bytes()) != sha(data):
            raise ValueError(f"Immutable pinned fixture changed: {file.name}")
        return
    fd = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)

def at(obj, path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj

def located(raw, name, expected):
    if expected is None or isinstance(expected, (list, dict, bool)):
        return None
    value = str(expected)
    if not value:
        return None
    # Independently asserted expected values, never supplied by our parser.
    if name == "pri":
        token = f"<{value}>"
        if not raw.startswith(token):
            return None
        start = 1
    elif name == "hostname":
        header = re.match(r"^<([0-9]{1,3})>[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2} +([^ ]+) +", raw)
        if not header or header.group(2) != value:
            return None
        start = header.start(2)
    elif name == "appname":
        header = re.match(r"^<([0-9]{1,3})>[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2} +[^ ]+ +([^ ]+) +", raw)
        if not header or header.group(2) != value:
            return None
        start = header.start(2)
    elif name == "message_id":
        header = re.match(r"^<([0-9]{1,3})>[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2} +[^ ]+ +[^ ]+ +([^ ]+) +", raw)
        if not header or header.group(2) != value:
            return None
        start = header.start(2)
    else:
        raise ValueError(name)
    end = start + len(value)
    if raw[start:end] != value:
        raise ValueError("Independent reference value/spans mismatch")
    start_byte = len(raw[:start].encode("utf-8"))
    end_byte = len(raw[:end].encode("utf-8"))
    if raw.encode("utf-8")[start_byte:end_byte].decode("utf-8") != value:
        raise ValueError("UTF-8 replay mismatch")
    return {"name": name, "value": value, "startByte": start_byte, "endByte": end_byte,
            "assertedSource": ".".join(next(p for n, p in SOURCE_MAP if n == name))}

def main():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    license_bytes = download("LICENSE.txt")
    if b"Elastic License" not in license_bytes:
        raise ValueError("Upstream source license unexpectedly changed")
    private_write(PRIVATE / "LICENSE.txt", license_bytes)
    manifest = {
        "repository": REPOSITORY, "upstreamRevision": REVISION,
        "license": "Elastic License 2.0 - evaluation fixtures private / not redistributed",
        "licenseSha256": sha(license_bytes), "files": [],
        "oracleStatus": "PUBLISHER_PARTIAL_ASSERTIONS_NOT_MANUFACTURER_OR_NATIVE_CERTIFICATION",
    }
    rows = []
    counts = {"events": 0, "eventsWithAssertions": 0, "sourceTriples": 0,
              "unscorableEvents": 0, "emptyAssignmentsUnscored": 0,
              "escapedInputEventsUnscoredSemantics": 0,
              "unmatchedExpected": 0}
    for stem in STEMS:
        pair = []
        for suffix in (".log", ".log-expected.json"):
            rel = f"{PATH}/{stem}{suffix}"
            data = download(rel)
            private_write(PRIVATE / f"{stem}{suffix}", data)
            pair.append(data)
            manifest["files"].append({"path": rel, "sha256": sha(data), "bytes": len(data)})
        logs = pair[0].decode("utf-8").splitlines()
        expected_list = json.loads(pair[1].decode("utf-8"))["expected"]
        if len(logs) != len(expected_list):
            raise ValueError("Upstream record/expectation cardinality differs")
        for ordinal, (raw, expected) in enumerate(zip(logs, expected_list)):
            if at(expected, ("event", "original")) != raw:
                raise ValueError("Original input and independently asserted event.original differ")
            counts["events"] += 1
            fields = []
            for name, path in SOURCE_MAP:
                observed = located(raw, name, at(expected, path))
                if observed is None:
                    counts["unmatchedExpected"] += 1
                else:
                    fields.append(observed)
            counts["sourceTriples"] += len(fields)
            counts["eventsWithAssertions"] += bool(fields)
            counts["unscorableEvents"] += not bool(fields)
            counts["emptyAssignmentsUnscored"] += ('=""' in raw or '=, ' in raw or ',,' in raw)
            counts["escapedInputEventsUnscoredSemantics"] += "\\" in raw
            rows.append({
                "raw": raw, "originalSha256": sha(raw.encode("utf-8")),
                "sourceFile": stem + ".log", "line": ordinal + 1,
                "qualification": "PUBLISHER_ASSERTED_PARTIAL_SOURCE_ONLY" if fields else "UNSCORABLE",
                "fields": fields,
                "decodedManufacturerEscape": "UNSCORABLE",
                "emptyVsNilVsAbsent": "UNSCORABLE",
                "native": "NOT_VERIFIED",
            })
    oracle = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    private_write(PRIVATE / "publisher-cisco-ise-oracle.v1.json", oracle)
    manifest["oracle"] = {
        "privateFile": "publisher-cisco-ise-oracle.v1.json",
        "sha256": sha(oracle), "counts": counts,
        "completeEventOracle": False, "fullFieldFP": "UNSCORABLE",
        "nativeParser": "NOT_VERIFIED",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    if PUBLIC.exists() and PUBLIC.read_bytes() != manifest_bytes:
        raise ValueError("Public pinned manifest drifted")
    if not PUBLIC.exists():
        PUBLIC.write_bytes(manifest_bytes)
    print(json.dumps({"upstream": REPOSITORY, "rev": REVISION,
        "licensedPrivateOnly": True, "oracleSha256": sha(oracle),
        "counts": counts, "sourceFiles": len(STEMS),
        "oracleFrozenBeforeCandidate": True,
        "valuesPrinted": False}, sort_keys=True))

if __name__ == "__main__":
    main()
