#!/usr/bin/env python3
"""Freeze RFC 5424 §6.3 independent authored grammar expectations before scoring."""
from pathlib import Path
import hashlib
import json

head = "<34>1 2026-10-18T12:34:56Z host app 123 E1 "
# Each positive expected item is authored before parser evaluation:
# (SD-ID, parameter name, exact wire lexeme, expected decoded value).
cases = [
    ("SD-BROWSER-UNKNOWN-BACKSLASH", r'[meta@32473 note="a\qb"]', "msg",
     [("meta@32473", "note", r"a\qb", r"a\qb")], True),
    ("SD-BROWSER-REPEATED-PARAM", '[meta@32473 note="one" note="two"]', "msg",
     [("meta@32473", "note", "one", "one"), ("meta@32473", "note", "two", "two")], True),
    ("SD-BROWSER-MIXED-UTF8", r'[meta@32473 note="€\q😀" note="second"]', "msg",
     [("meta@32473", "note", "€\\q😀", "€\\q😀"), ("meta@32473", "note", "second", "second")], True),
    ("SD-BROWSER-DEFINED-ESCAPES", r'[meta@32473 path="a\]b\\c\"d"]', "msg",
     [("meta@32473", "path", r'a\]b\\c\"d', 'a]b\\c"d')], True),
    ("SD-BROWSER-LEGAL-SD-NAME", r'[dev[ice@32473 field\name="v"]', "msg",
     [("dev[ice@32473", r"field\name", "v", "v")], True),
    ("SD-BROWSER-TWO-ELEMENTS", '[meta@32473 n="1"][next@32473 x="€"]', "msg",
     [("meta@32473", "n", "1", "1"), ("next@32473", "x", "€", "€")], True),
    ("SD-BROWSER-INVALID-DUPLICATE-ID", '[meta@32473 x="a"][meta@32473 x="b"]', "msg", [], False),
    ("SD-BROWSER-INVALID-RAW-RBRACKET", '[meta@32473 x="a]b"]', "msg", [], False),
    ("SD-BROWSER-INVALID-UNTERMINATED", '[meta@32473 x="unclosed]', "msg", [], False),
    ("SD-BROWSER-INVALID-UNQUOTED", '[meta@32473 x=a]', "msg", [], False),
]

frozen = []
for case_id, sd, msg, fields, valid in cases:
    wire = head + sd + " " + msg
    ordered = []
    search_cursor = 0
    for sd_id, name, lexical, decoded in fields:
        marker = name + '="' + lexical + '"'
        at = sd.find(marker, search_cursor)
        if at < 0:
            raise RuntimeError(f"{case_id}: expected lexical marker absent: {marker!r}")
        name_start = len((head + sd[:at]).encode("utf-8"))
        value_start = len((head + sd[:at + len(name) + 2]).encode("utf-8"))
        value_end = value_start + len(lexical.encode("utf-8"))
        assert wire.encode()[value_start:value_end] == lexical.encode("utf-8")
        ordered.append({
            "sdId": sd_id, "name": name, "rawLexeme": lexical,
            "decoded": decoded, "nameStart": name_start, "nameEnd": name_start + len(name.encode("ascii")),
            "valueStart": value_start, "valueEnd": value_end,
        })
        search_cursor = at + len(marker)
    frozen.append({
        "id": case_id, "wire": wire, "sdRaw": sd, "message": msg,
        "valid": valid, "expected": ordered,
        "eventBytes": len(wire.encode("utf-8")),
        "sdStart": len(head.encode("utf-8")),
        "sdEnd": len((head + sd).encode("utf-8")),
    })
obj = {
    "provenance": "independently authored standards-derived synthetic; RFC5424 sections 6.3.2/6.3.3; NOT publisher or native evidence",
    "cases": frozen,
}
raw = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
path = Path("scripts/poc/standardsRfc5424BrowserParity.pinned.json")
path.write_bytes(raw)
print(f"FROZEN {path} CASES={len(frozen)} SHA256={hashlib.sha256(raw).hexdigest()}")
