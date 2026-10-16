#!/usr/bin/env python3
"""Fetch pinned public raw security-log fixtures into an isolated local evaluation directory."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen

MANIFEST = Path(__file__).with_name("publicSecurityHoldout.manifest.json")
PAN_TYPES = (
    "TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|"
    "DECRYPTION|HIPMATCH|AUTHENTICATION|GTP|IPTAG|SCTP|TUNNEL|URL|DATA|WILDFIRE"
)
PAN_START = re.compile(
    r"(?:^| )(?P<body>\d{1,10},\d{4}/\d{2}/\d{2} "
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?,[^,]*,(?:" + PAN_TYPES + r"),)"
)
PAN_AUDIT = re.compile(
    r"(?:^| )(?P<body>\d{8,20},\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},audit,)"
)


def write_private(path: Path, content: object) -> None:
    path.write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
    os.chmod(path, 0o600)


def source_identity(relative_path: str) -> str:
    parts = relative_path.split("/")
    group = parts[0]
    file_name = parts[-1]
    if group == "panw":
        assert file_name.startswith("test-panw-panos-") and file_name.endswith("-sample.log")
        name = file_name.removeprefix("test-panw-panos-").removesuffix("-sample.log")
    elif group == "cisco_umbrella":
        assert file_name.startswith("test-umbrella-") and file_name.endswith(".log")
        name = file_name.removeprefix("test-umbrella-").removesuffix(".log")
    else:
        assert file_name.startswith("test-") and file_name.endswith(".log")
        name = file_name.removeprefix("test-").removesuffix(".log")
    return group + "/" + ("panos" if group == "panw" else parts[2]) + "/" + name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path,
        default=Path.home() / ".local/state/parserstudio-ext-holdout-20261016",
        help="Private output directory; raw events are never placed in the repository.",
    )
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    revision = manifest["revision"]
    assert re.fullmatch("[0-9a-f]{40}", revision)
    root = args.output.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    base = manifest["repository"].removesuffix("/") + "/"
    assert base == "https://github.com/elastic/integrations/"
    raw_base = "https://raw.githubusercontent.com/elastic/integrations/" + revision + "/packages/"
    records: list[dict[str, str]] = []
    for item in manifest["files"]:
        relative = item["path"]
        assert ".." not in relative and relative.endswith(".log")
        request = Request(raw_base + relative, headers={"User-Agent": "ParserStudioPublicHoldout/1"})
        with urlopen(request, timeout=25) as response:
            content = response.read()
        assert hashlib.sha256(content).hexdigest() == item["sha256"], "Upstream SHA mismatch: " + relative
        assert len(content) == item["bytes"], "Upstream byte count changed: " + relative
        lines = [line for line in content.decode("utf-8-sig").splitlines() if line.strip()]
        assert len(lines) == item["records"], "Upstream row count changed: " + relative
        source = source_identity(relative)
        records.extend(
            {"id": source + "#" + str(i + 1), "source": source, "raw": line}
            for i, line in enumerate(lines)
        )
    assert len(records) == 790, "Unexpected source event count"
    oracle: dict[str, dict[str, object]] = {}
    for row in records:
        raw = row["raw"]
        source = row["source"]
        if source.startswith("panw/"):
            marker = PAN_START.search(raw) or PAN_AUDIT.search(raw)
            if not marker:
                continue
            payload, kind = raw[marker.start("body"):], "pan"
        elif source.startswith("cisco_umbrella/"):
            payload, kind = raw, "umbrella"
        else:
            continue
        values = next(csv.reader([payload], strict=True, skipinitialspace=kind == "umbrella"))
        oracle[row["id"]] = {"kind": kind, "values": values, "offset": len(raw) - len(payload)}
    assert len(oracle) == 766, "Unexpected independent CSV reference coverage"
    mutations: list[dict[str, str]] = []
    for row in records:
        if row["id"] not in oracle:
            continue
        raw = row["raw"]
        kind = oracle[row["id"]]["kind"]
        date = re.search(r"20\d{2}/\d{2}/\d{2}", raw) if kind == "pan" else re.search(r"20\d{2}-\d{2}-\d{2}", raw)
        if date:
            bad_date = "2026/02/30" if kind == "pan" else "2026-02-30"
            mutations.append(
                {"id": row["id"] + "/invalid-calendar", "source": row["source"],
                 "raw": raw[:date.start()] + bad_date + raw[date.end():]}
            )
        mutations.append(
            {"id": row["id"] + "/unclosed-quote", "source": row["source"],
             "raw": raw + ',"never-closed'}
        )
    assert len(mutations) == 1532, "Unexpected mutation count"
    write_private(root / "records.json", records)
    write_private(root / "csv_oracle.json", oracle)
    write_private(root / "adversarial.json", mutations)
    print(json.dumps({
        "upstream_revision": revision, "sources": len(manifest["files"]),
        "events": len(records), "independent_csv_rows": len(oracle),
        "adversarial_events": len(mutations),
        "raw_corpus_sha256": hashlib.sha256((root / "records.json").read_bytes()).hexdigest(),
    }))


if __name__ == "__main__":
    main()
