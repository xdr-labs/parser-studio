#!/usr/bin/env python3
"""Pin independent public security-log sources without exposing original values.

This acquisition tool never calls a Parser Studio candidate. It is deliberately
separate from the evaluation runner and never commits customer/sample content.
"""
import hashlib
import json
import os
from pathlib import Path
import urllib.request

STATE = Path.home() / ".local/state/parserstudio-generalization-blind-20261017"
PUBLIC = Path(__file__).with_name("generalizationSources.pinned.json")
SOURCES = {
    "suricata_pcap": {
        "repo": "FrankHassanabad/suricata-sample-data",
        "revision": "2d94c5d73f0d7b652b2adc13b81806048d08ba18",
        "license": "MIT",
        "origin": "suricata_generated_from_public_pcap",
        "files": [
            "samples/first-org-conf-2015/alerts-only.json",
            "samples/honeypot-2018/alerts-only.json",
            "samples/wrccdc-2017/alerts-only.json",
            "samples/wrccdc-2018/alerts-only.json",
        ],
    },
    "converter_upstream": {
        "repo": "allamiro/JSON-SYSLOG-TO-CEF",
        "revision": "da4dd154e2393b4921f3305da92e76b6e2288194",
        "license": "Apache-2.0",
        "origin": "public_conversion_test_samples_not_device_attested",
        "files": [
            "samples/ecs.ndjson",
            "tests/data/audit.log",
            "tests/data/cisco-ios.json",
            "tests/data/cisco-ios.log",
        ],
    },
    "log_zoo": {
        "repo": "sva-s1/log-zoo",
        "revision": "f61b0d7f345f47349a376629bfc3165752b77ade",
        "license": "CC0_claimed_in_README",
        "origin": "public_vendored_originals_not_device_attested",
        "files": [
            "cef/xypro_nonstop_object_access.log",
            "fortinet/event.type/security-rating/fortigate.log",
            "fortinet/event.type/system/fortigate.log",
            "fortinet/event.type/traffic/fortigate.log",
        ],
    },
    "siem_examples": {
        "repo": "TanayBhatt26/siem-log-parser",
        "revision": "d5a821af51b03a4767aeeb6d7619455a6bfbe606",
        "license": "UNSPECIFIED_RESEARCH_ONLY",
        "origin": "public_example_not_original_verified",
        "files": [
            "sample_logs/sample.aws.json",
            "sample_logs/sample.json",
            "sample_logs/sample.cef",
            "sample_logs/sample.leef",
            "sample_logs/sample.syslog",
            "sample_logs/sample.zeek.log",
        ],
    },
}


def _private_write(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError("Frozen source changed: " + path.name)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)


def main() -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    raw_dir = STATE / "raw"
    raw_dir.mkdir(mode=0o700, exist_ok=True)
    entries = []
    for family, source in SOURCES.items():
        for index, relative in enumerate(source["files"]):
            name = f"{family}-{index:02d}.bin"
            url = f"https://raw.githubusercontent.com/{source['repo']}/{source['revision']}/{relative}"
            req = urllib.request.Request(url, headers={"User-Agent": "ParserStudio-Accuracy-Blind-Pin"})
            with urllib.request.urlopen(req, timeout=20) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if not data or len(data) > 2 * 1024 * 1024:
                raise RuntimeError("Empty/oversized public sample: " + name)
            _private_write(raw_dir / name, data)
            entries.append({
                "id": name.removesuffix(".bin"),
                "family": family,
                "repo": source["repo"],
                "revision": source["revision"],
                "source_path": relative,
                "license": source["license"],
                "origin": source["origin"],
                "raw_sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "overlap_previous_repo": source["repo"] == "elastic/integrations",
                "claimed_original_device": False,
            })
    pinned = {"schema": "generalization-source-pins-v1",
              "stage": "PINNED_BEFORE_ANY_CANDIDATE_SCORING",
              "read_only_raw_state": str(raw_dir),
              "source_files": entries,
              "raw_publication": "never_commit",
              "semantics": "unknown_until_independent_oracle"}
    serialized = (json.dumps(pinned, indent=2, ensure_ascii=True) + "\n").encode()
    _private_write(STATE / "sources.pinned.json", serialized)
    if PUBLIC.exists() and PUBLIC.read_bytes() != serialized:
        raise RuntimeError("Existing public pinned manifest would change")
    PUBLIC.write_bytes(serialized)
    print(json.dumps({"stage": pinned["stage"], "files": len(entries),
                      "bytes": sum(item["bytes"] for item in entries),
                      "unique_sha": len({x["raw_sha256"] for x in entries}),
                      "repo_overlap": sum(x["overlap_previous_repo"] for x in entries)}))


if __name__ == "__main__":
    main()
