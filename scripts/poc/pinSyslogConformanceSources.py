#!/usr/bin/env python3
"""Pin independent upstream Syslog conformance tests before parser scoring.

Only a source file manifest with hashes and non-sensitive metadata is published.
Original third-party test source and expected values remain private (0600).
"""
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

STATE = Path.home() / ".local/state/parserstudio-syslog-conformance-20261017"
PUBLIC = Path(__file__).with_name("syslogConformanceSources.pinned.json")
SOURCES = [
    ("influx_rfc3164", "influxdata/go-syslog",
     "66067a10754ae90b9540d5312989ae685413c4fe",
     "rfc3164/machine_test.go", "MIT", "development"),
    ("influx_rfc5424", "influxdata/go-syslog",
     "66067a10754ae90b9540d5312989ae685413c4fe",
     "rfc5424/machine_test.go", "MIT", "development"),
    ("otel_syslog", "open-telemetry/opentelemetry-collector-contrib",
     "7c913688e177b4f76270b9a04f5eef3f48e5008f",
     "pkg/stanza/operator/parser/syslog/syslogtest/data.go", "Apache-2.0", "sealed"),
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def freeze_private(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError("Pinned content unexpectedly changed")
        return
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(content)


def main() -> None:
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    private = STATE / "upstream"
    private.mkdir(mode=0o700, exist_ok=True)
    items = []
    for source_id, repo, revision, rel, license_id, split in SOURCES:
        request = Request(
            f"https://raw.githubusercontent.com/{repo}/{revision}/{rel}",
            headers={"User-Agent": "ParserStudio-Independent-Syslog-Conformance"},
        )
        with urlopen(request, timeout=22) as response:
            original = response.read(1024 * 1024 + 1)
        if not original or len(original) > 1024 * 1024:
            raise RuntimeError("Unexpected size for upstream conformance source")
        freeze_private(private / (source_id + ".go"), original)
        items.append({"id": source_id, "repository": repo, "revision": revision,
                      "path": rel, "license": license_id, "split": split,
                      "byte_count": len(original), "sha256": sha(original),
                      "upstream_expected_values": True,
                      "manufacturer_device_attested": False})
    content = {
        "schema": "syslog-conformance-source-pins-v1",
        "state": "PINNED_BEFORE_ANY_BASELINE_OR_CANDIDATE_INSPECTION",
        "files": items,
        "raw_policy": "private_0600_not_in_git",
        "comparison": "upstream_expected_source_header_semantics_plus_original_bytes",
        "experimental_limit": "public_library_unit_fixtures_not_authentic_device_captures",
    }
    serialized = (json.dumps(content, indent=2, ensure_ascii=True) + "\n").encode()
    freeze_private(STATE / "sources.pinned.json", serialized)
    if PUBLIC.exists() and PUBLIC.read_bytes() != serialized:
        raise RuntimeError("Cannot overwrite published pins")
    PUBLIC.write_bytes(serialized)
    print(json.dumps({"stage": content["state"], "sources": len(items),
                      "bytes": sum(x["byte_count"] for x in items),
                      "unique_sha": len(set(x["sha256"] for x in items)),
                      "sealed_sources": sum(x["split"] == "sealed" for x in items)}))


if __name__ == "__main__":
    main()
