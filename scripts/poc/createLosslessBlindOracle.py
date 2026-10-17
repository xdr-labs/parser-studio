#!/usr/bin/env python3
"""Independent Python source-field references for a second frozen public dataset."""
from __future__ import annotations

import json
import os
from pathlib import Path

from createLosslessIndependentOracle import (
    DELIMITERS, independent_fields, independent_prefixed_source,
)

ROOT = Path.home()/".local/state/parserstudio-lossless-blind-20261017"


def pinned_write(name: str, item: object) -> None:
    file=ROOT/name
    serialized=json.dumps(item,sort_keys=True,ensure_ascii=False)
    if file.exists():
        if file.read_text()!=serialized:
            raise ValueError(f"Refusing to modify frozen oracle {name}")
    else:
        file.write_text(serialized)
        os.chmod(file,0o600)


def main() -> None:
    samples=json.loads((ROOT/"records.json").read_text())
    flat={}
    prefixed={}
    for row in samples:
        dialects={sep: fields for sep in DELIMITERS
                  if (fields := independent_fields(row["raw"], sep)) is not None}
        if dialects:
            flat[row["id"]]=dialects
        prefix=independent_prefixed_source(row["raw"])
        if prefix is not None:
            prefixed[row["id"]]=prefix
    pinned_write("oracle-flat.json",flat)
    pinned_write("oracle-prefix.json",prefixed)
    summary={"records":len(samples),"flat_events":len(flat),"prefix_events":len(prefixed)}
    pinned_write("oracle-summary.json",summary)
    print(json.dumps(summary))


if __name__=="__main__":
    main()
