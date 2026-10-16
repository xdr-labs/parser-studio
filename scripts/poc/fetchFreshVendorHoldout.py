#!/usr/bin/env python3
"""Fetch pinned four-vendor security fixtures and preserve logical JSON event boundaries."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

MANIFEST = Path(__file__).with_name("freshVendorHoldout.manifest.json")
DEFAULT_OUTPUT = Path.home() / ".local/state/parserstudio-fresh-vendor-holdout-20261016"

def write_private(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)

def split_json_documents(raw_lines: list[str], source: str) -> tuple[list[dict[str,str]], list[dict[str,str]]]:
    text = "\n".join(raw_lines)
    decoder = json.JSONDecoder()
    position, sequence = 0, 0
    positives: list[dict[str,str]] = []
    negatives: list[dict[str,str]] = []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        value, end = decoder.raw_decode(text, position)
        sequence += 1
        record = {"id": f"{source}#{sequence}", "source": source, "raw": text[position:end]}
        if isinstance(value, (dict, list)):
            positives.append(record)
        else:
            negatives.append(record)
        position = end
    return positives, negatives

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    destination = args.output.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    revision = manifest["revision"]
    assert len(revision) == 40 and all(c in "0123456789abcdef" for c in revision)
    assert manifest["repository"] == "https://github.com/elastic/integrations"

    records: list[dict[str,str]] = []
    negatives: list[dict[str,str]] = []
    for entry in manifest["files"]:
        relative = entry["path"]
        assert relative.startswith("packages/") and ".." not in relative and relative.endswith(".log")
        request = Request(
            f"https://raw.githubusercontent.com/elastic/integrations/{revision}/{relative}",
            headers={"User-Agent": "ParserStudioFreshVendorHoldout/1"},
        )
        with urlopen(request, timeout=30) as response:
            content = response.read()
        assert len(content) == entry["bytes"], f"File byte count changed: {relative}"
        assert hashlib.sha256(content).hexdigest() == entry["sha256"], f"File SHA mismatch: {relative}"
        lines = [line for line in content.decode("utf-8-sig").splitlines() if line.strip()]
        assert len(lines) == entry["records"], f"File line count changed: {relative}"

        parts = relative.split("/")
        source = "/".join((parts[1], parts[3], parts[-1]))
        if parts[1] == "crowdstrike":
            positive, negative = split_json_documents(lines, source)
            records.extend(positive)
            negatives.extend(negative)
        else:
            records.extend(
                {"id": f"{source}#{i+1}", "source": source, "raw": line}
                for i, line in enumerate(lines)
            )

    assert len(records) == 571, f"Unexpected event count: {len(records)}"
    assert len(negatives) == 1, f"Unexpected known-invalid control count: {len(negatives)}"
    write_private(destination / "records.json", records)
    write_private(destination / "known_invalid.json", negatives)
    print(json.dumps({
        "revision": revision,
        "files": len(manifest["files"]),
        "security_events": len(records),
        "known_invalid_json_scalars": len(negatives),
        "record_sha256": hashlib.sha256((destination / "records.json").read_bytes()).hexdigest(),
    }))

if __name__ == "__main__":
    main()
