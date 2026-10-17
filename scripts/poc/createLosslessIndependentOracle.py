#!/usr/bin/env python3
"""Build private independent shlex source-field oracles from frozen Elastic inputs.

Source-native flat key=value rows only. This deliberately does not confer
vendor normalization, field types or parser compatibility.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex

SOURCE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}")
UNSAFE = {"__proto__", "constructor", "prototype"}
DELIMITERS = {"space": " \t", "pipe": "|", "semicolon": ";", "tab": "\t", "comma": ","}
SOURCE_HEAD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}=")


def independent_fields(raw: str, grammar: str) -> dict[str, str] | None:
    if len(raw.encode("utf8")) > 16384 or "\0" in raw or "\n" in raw or "\r" in raw:
        return None
    if not SOURCE_HEAD.match(raw):
        return None
    lex = shlex.shlex(raw, posix=True)
    lex.commenters = ""
    lex.whitespace = DELIMITERS[grammar]
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError:
        return None
    if not 2 <= len(tokens) <= 256:
        return None
    fields: dict[str, str] = {}
    normalized: set[str] = set()
    for token in tokens:
        if "=" not in token:
            return None
        key, value = token.split("=", 1)
        collision = key.replace("-", "_")
        if not SOURCE_KEY.fullmatch(key) or key in UNSAFE or collision in UNSAFE or collision in normalized:
            return None
        fields[key] = value
        normalized.add(collision)
    return fields


def independent_prefixed_source(raw: str) -> dict[str, object] | None:
    prefix = re.match(
        r"^([^=\s]{1,255})[ \t]+(?=[A-Za-z_][A-Za-z0-9_.-]{0,127}=)",
        raw,
    )
    if prefix is None:
        return None
    try:
        ipaddress.ip_address(prefix.group(1))
    except ValueError:
        return None
    suffix = raw[prefix.end():]
    lex = shlex.shlex(suffix, posix=True)
    lex.commenters = ""
    lex.whitespace = " \t"
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError:
        return None
    if not 2 <= len(tokens) <= 256:
        return None
    entries: list[list[str]] = []
    normalized: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            return None
        key, value = token.split("=", 1)
        canonical = key.replace("-", "_")
        if not SOURCE_KEY.fullmatch(key) or key in UNSAFE or canonical in UNSAFE:
            return None
        if canonical in normalized and normalized[canonical] != key:
            return None
        normalized[canonical] = key
        entries.append([key, value])
    return {"prefix": raw[:prefix.end()], "fields": entries}


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--split", choices=("development", "evaluation"), required=True)
    cli.add_argument("--source", type=Path, default=
        Path.home()/".local/state/parserstudio-lossless-fresh-20261017")
    args = cli.parse_args()
    root = args.source.expanduser()
    split = json.loads((root/"split.json").read_text())
    files = set(split[args.split+"_files"])
    rows = json.loads((root/"records.json").read_text())
    oracle = {}
    for row in rows:
        if row["source"] not in files:
            continue
        grammars = {kind: found for kind in DELIMITERS
                    if (found := independent_fields(row["raw"], kind)) is not None}
        if grammars:
            oracle[row["id"]] = grammars
    prefixed = {
        row["id"]: result
        for row in rows
        if row["source"] in files
        if (result := independent_prefixed_source(row["raw"])) is not None
    }
    prefix_content = json.dumps(prefixed, sort_keys=True, ensure_ascii=False)
    prefix_dest = root/("oracle-prefixed-"+args.split+".json")
    if prefix_dest.exists():
        if prefix_dest.read_text() != prefix_content:
            raise ValueError("Refusing to rewrite pinned independent prefix oracle")
    else:
        prefix_dest.write_text(prefix_content)
        os.chmod(prefix_dest, 0o600)
    content = json.dumps(oracle, sort_keys=True, ensure_ascii=False)
    dest = root/("oracle-"+args.split+".json")
    if dest.exists():
        if dest.read_text() != content:
            raise ValueError("Refusing to rewrite frozen independent source oracle")
    else:
        dest.write_text(content)
        os.chmod(dest, 0o600)
    print(json.dumps({"split":args.split,"events":len([row for row in rows if row["source"] in files]),
        "oracle_events":len(oracle),
        "oracle_grammars":sum(len(v) for v in oracle.values()),
        "prefixed_oracle_events":len(prefixed)}))


if __name__ == "__main__":
    main()
