#!/usr/bin/env python3
"""Controlled GPT-6 role exercise for source-bound one-log ParserRecipe v0.2 prompts.

These authored responses are NOT independently sampled provider completions.
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path("/home/aella/.local/state/parserstudio-expanded-security-20261025")
OUT = ROOT / "new-grammar-recovery"
ROWS = {x["id"]: x for x in json.loads((ROOT / "additional-source-manifest.json").read_text())["cases"]}
VALID = {"fortinet-058", "juniper-061", "watchguard-062", "cisco-068",
         "cisco-073", "zeek-077", "zeek-078", "microsoft-081"}
REFUSE = {
    "palo_alto_networks-059": "The one unlabeled PAN-OS positional source row lacks an independently declared column schema and exposes a leading relay prefix. Provide the matching field order/schema for this export and a second event of the same type; do not guess semantic indexes.",
    "cisco-060": "One synthetic ASA connection message is insufficient to prove a generic parser for changing message IDs, optional NAT endpoint pairs and header variants. Provide a declared ASA log template or at least two different genuine connection examples with the intended fields.",
    "zeek-075": "This is only a Zeek #separator metadata declaration, not an event. Provide the complete #fields schema and at least one tab-delimited data record in one input.",
    "zeek-076": "This is only a Zeek #fields schema line, not an event. Provide the delimiter declaration and a matching complete data record with it.",
    "microsoft-079": "This is solely a W3C #Version metadata row. Provide the #Fields schema followed by real log records.",
    "microsoft-080": "This is solely a W3C #Fields metadata row without any event. Provide an actual matching data row in the same input.",
    "microsoft-086": "Windows Event XML is not a supported ParserRecipe v0.2 source grammar. Export this event as intact JSON, CEF or a reviewed supported text format; do not invent XML parsing support."
}
assert VALID.isdisjoint(REFUSE)
assert len(VALID) + len(REFUSE) == 15

def digest(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def stage_map(source: str, *, target: str | None = None, typ="string", group="vendor_fields"):
    return [{"op": "map_field", "source": source, "target": target or source,
             "data_type": typ, "group": group}] + (
        [{"op": "cast_type", "target": target or source, "data_type": typ}]
        if typ != "string" else []
    )

def recipe(case: str, source_format: str, parse: dict, columns: list[tuple[str,str,str]]):
    c = ROWS[case]
    prompt = (OUT / case / "prompt-1.txt").read_text()
    match = re.search(r'"projectId":"(draft-[a-z][a-z0-9_]+)","sourceHash":"([a-f0-9]{64})","sourceCount":1', prompt)
    assert match, case
    assert match.group(2) == c["originalSha256"], case
    stage = [{"op": "split_event", "boundary": "single-line"}, parse]
    for source, typ, group in columns:
        stage.extend(stage_map(source, typ=typ, group=group))
    stage.extend([
        {"op": "classify", "defaultIndex": "syslog", "rules": []},
        {"op": "fallback_unparsed", "mode": "retain_unparsed"}
    ])
    return {"contract": "parser-studio.recipe.v0.2",
            "schemaRevision": "0.2", "compilerMode": "REVIEW_ONLY",
            "projectId": match.group(1), "sourceFormat": source_format,
            "bodyFormat": source_format,
            "sample": {"sha256": c["originalSha256"], "events": 1},
            "stages": stage, "nativeVerified": False, "targetVerified": False}

def regex(case: str, pattern: str, specs: list[tuple[str,str,str]]):
    assert len(pattern) <= 256, (case, len(pattern))
    p = re.compile(pattern.replace("(?<", "(?P<"))
    match = p.fullmatch(ROWS[case]["rawSample"])
    assert match, (case, "not matching source")
    assert set(match.groupdict()) == {source for source, typ, group in specs}
    assert all(match.group(source) for source, typ, group in specs)
    return recipe(case, "regex", {"op": "parse_regex", "pattern": pattern}, specs)

P = {}
P["fortinet-058"] = recipe("fortinet-058", "kv", {"op": "parse_kv"}, [
    (name, typ, group) for name, typ, group in (
      ("date","string","vendor_fields"), ("time","string","vendor_fields"),
      ("devname","string","vendor_fields"), ("devid","string","vendor_fields"),
      ("type","string","top_fields"), ("subtype","string","vendor_fields"),
      ("level","string","vendor_fields"), ("srcip","ip","top_fields"),
      ("dstip","ip","top_fields"), ("srcport","integer","top_fields"),
      ("dstport","integer","top_fields"), ("action","string","top_fields"),
      ("service","string","vendor_fields"))
])
P["juniper-061"] = regex("juniper-061",
  r"^<\d+>[A-Z][a-z]{2} \d{1,2} [\d:]+ \S+ RT_FLOW: RT_FLOW_SESSION_DENY: session denied (?<srcip>[^/ ]+)/(?<srcport>\d+)->(?<dstip>[^/ ]+)/(?<dstport>\d+) .+$",
  [("srcip","ip","top_fields"),("srcport","integer","top_fields"),
   ("dstip","ip","top_fields"),("dstport","integer","top_fields")])
P["watchguard-062"] = regex("watchguard-062",
  r"^<\d+>[A-Z][a-z]{2} \d{1,2} [\d:]+ \S+ firewall: (?<decision>\w+) (?<srcip>\S+) (?<dstip>\S+) (?<protocol>\w+) (?<srcport>\d+) (?<dstport>\d+) policy=(?<policy>\S+) action=(?<action>\S+)$",
  [("decision","string","vendor_fields"),("srcip","ip","top_fields"),
   ("dstip","ip","top_fields"),("protocol","string","vendor_fields"),
   ("srcport","integer","top_fields"),("dstport","integer","top_fields"),
   ("policy","string","vendor_fields"),("action","string","top_fields")])
P["cisco-068"] = regex("cisco-068",
  r'^(?<clock>\S+) \[\*\*\] \[(?<signature_id>[\d:]+)\] "(?<message>[^"]+)" \[\*\*\] \[Classification: (?<classification>[^\]]+)\] \[Priority: (?<priority>\d+)\] \[AppID: (?<appid>[^\]]+)\] \{(?<protocol>\w+)\} (?<src_endpoint>\S+) -> (?<dst_endpoint>\S+)$',
  [(name,"string","vendor_fields") for name in
   ["clock","signature_id","message","classification","priority","appid","protocol",
    "src_endpoint","dst_endpoint"]])
csv6=["column_1","column_2","column_3","column_4","column_5","column_6"]
P["cisco-073"] = recipe("cisco-073", "csv",
 {"op":"parse_csv","columns":csv6,"delimiter":","},
 [(name,"string","vendor_fields") for name in csv6])
csv5=["column_1","column_2","column_3","column_4","column_5"]
for case in ("zeek-077","zeek-078"):
    P[case]=recipe(case,"csv",{"op":"parse_csv","columns":csv5,"delimiter":"\t"},
      [(name,"string","vendor_fields") for name in csv5])
P["microsoft-081"] = regex("microsoft-081",
  r"^(?<column_1>\d{4}-\d{2}-\d{2}) (?<column_2>\d{2}:\d{2}:\d{2}) (?<column_3>\S+) (?<column_4>\S+) (?<column_5>\S+) (?<column_6>\d{3})$",
  [(name,"string","vendor_fields") for name in csv6])
assert set(P)==VALID

matrix=[]
for case in sorted(VALID | set(REFUSE)):
    c=ROWS[case];prompt=(OUT/case/"prompt-1.txt").read_text()
    assert c["rawSample"] in prompt and c["originalSha256"] in prompt
    response=json.dumps(P[case],separators=(",",":"),ensure_ascii=False) if case in VALID else \
        "REVIEW_REQUIRED: " + REFUSE[case]
    folder=OUT/case
    dest=folder/"response-1.txt"
    assert not dest.exists() or dest.read_text()==response,"CHANGED_EXISTING_MODEL_RESPONSE"
    dest.write_text(response)
    receipt={"origin":"SAME_CHAT_GPT6",
      "model":"GPT-6","replyMode":"MODEL_AUTHORED_NEW_GRAMMAR" if case in VALID else "REVIEW_REQUIRED",
      "promptSha256":digest(prompt),"responseSha256":digest(response),
      "attribution":"Controlled user/model simulation; NOT independently invoked ChatGPT API/website"}
    (folder/"capture-1.json").write_text(json.dumps(receipt,indent=2))
    matrix.append({"id":case,"type":receipt["replyMode"],
                   "responseSha256":receipt["responseSha256"]})
    print("MODEL_ROLE",case,receipt["replyMode"],"bytes",len(response))
(OUT/"authored-matrix.json").write_text(json.dumps(matrix,indent=2))
