#!/usr/bin/env python3
"""Freeze synthetic CEF v26 header grammar claims before candidate scoring."""
from pathlib import Path
import hashlib
import json

names = ["cefVersion", "deviceVendor", "deviceProduct", "deviceVersion",
         "deviceEventClassId", "name", "severity"]

def pair(wire, decoded=None):
    return (wire, wire if decoded is None else decoded)

valid = [
    ("CEF-UTF8-PIPE", [pair("0"), pair("Exämple"), pair("IPS"), pair("1"),
      pair("E1"), pair(r"blocked a \| pipe", "blocked a | pipe"), pair("5")], "src=192.0.2.1"),
    ("CEF-BACKSLASH", [pair("1"), pair("Vendor"), pair("EDR"), pair("2"),
      pair("E2"), pair(r"a\\b", r"a\b"), pair("Unknown")], "src=198.51.100.8"),
    ("CEF-NAMED-HIGH", [pair("0"), pair("V"), pair("P"), pair("1"),
      pair("E1"), pair("Event"), pair("Very-High")], ""),
    ("CEF-ZERO", [pair("0"), pair("V"), pair("P"), pair("1"),
      pair("E1"), pair("Event"), pair("0")], "act=allow"),
    ("CEF-TEN", [pair("0"), pair("V"), pair("P"), pair("1"),
      pair("E1"), pair("Event"), pair("10")], "act=deny"),
    ("CEF-NAMED-MEDIUM", [pair("0"), pair("V"), pair("P"), pair("1"),
      pair("E1"), pair("Event"), pair("Medium")], "spt=443"),
]
invalid = [
    ("CEF-BLANK-VENDOR", "CEF:0||IDS|1|E1|Alert|5|src=192.0.2.1"),
    ("CEF-BLANK-SEVERITY", "CEF:0|V|P|1|E1|Alert||src=192.0.2.1"),
    ("CEF-SEVERITY-99", "CEF:0|V|P|1|E1|Alert|99|src=192.0.2.1"),
    ("CEF-UNKNOWN-HEADER-ESCAPE", r"CEF:0|V|P|1|E1|bad \q|5|src=192.0.2.1"),
    ("CEF-UNSUPPORTED-VERSION", "CEF:2|V|P|1|E1|Alert|5|src=192.0.2.1"),
    ("CEF-BLANK-EVENT-NAME", "CEF:0|V|P|1|E1||5|src=192.0.2.1"),
    ("CEF-MISSING-SEPARATOR", "CEF:0|V|P|1|E1|Alert|5"),
]
cases = []
for identifier, fields, ext in valid:
    wire = "CEF:" + "|".join(x[0] for x in fields) + "|" + ext
    cursor = len("CEF:")
    expected = []
    for name,(lex,decoded) in zip(names,fields):
        assert wire[cursor:cursor+len(lex)] == lex
        begin = len(wire[:cursor].encode("utf8"))
        end = len(wire[:cursor+len(lex)].encode("utf8"))
        assert wire.encode("utf8")[begin:end] == lex.encode("utf8")
        expected.append({"name":name, "lexeme":lex,"decoded":decoded,
                         "startByte":begin, "endByte":end})
        cursor+=len(lex)+1
    cases.append({"id":identifier,"wire":wire,"valid":True,
                  "extension":ext,"fields":expected,"sourceBytes":len(wire.encode("utf8"))})
for identifier,wire in invalid:
    cases.append({"id":identifier,"wire":wire,"valid":False,"fields":[],
                  "sourceBytes":len(wire.encode("utf8"))})
data={"evidence":"authored CEF v26 format grammar; synthetic only; no device/native scoring",
      "cases":cases}
raw=(json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode("utf8")
output=Path("scripts/poc/standardCefHeaderParity.pinned.json")
output.write_bytes(raw)
print("FROZEN",output,"CASES",len(cases),"SHA256",hashlib.sha256(raw).hexdigest())
