"""Runs the Python Multi-Pass header entry points for the Semantic Oracle.

Input (stdin, JSON):
  {"moduleDir": "<directory that holds the Multi-Pass modules>",
   "lines": ["<raw line>", ...],
   "kvLines": ["<raw line with a key=value body>", ...],
   "familyLines": [{"family": "cef" | "leef", "raw": "<raw line>"}, ...],
   "versions": ["1", "2", ...]}
Output (stdout, JSON):
  {"python": "<version>",
   "envelope": [null | {"syslog": {...}, "start": <payload offset>}, ...],
   "kv": [{"status": "<preview status>", "body": {<key>: <value> | [<values>]}}, ...],
   "family": [{"status": "<preview status>", "header": {...}, "extension": {...}}, ...],
   "rfc5424": {"<version>": {"extract_rfc5424": bool, "extract_pair_envelope": bool,
                             "short_rfc5424_json": bool, "short_ietf_csv": bool,
                             "parse_generic_structural": bool}}}

`rfc5424` answers, per VERSION, whether each RFC 5424 entry point of the engine
accepted a line that is valid in every other respect. The module directory is a
parameter so the oracle can run the same probes against a copy with an injected
fault. Standard library only; no network, no files written.
"""
import json
import sys

sys.dont_write_bytecode = True
request = json.load(sys.stdin)
sys.path.insert(0, request["moduleDir"])

import generic_structural_poc  # noqa: E402
import multipass_preview_api  # noqa: E402
import security_envelope  # noqa: E402
import security_pairs  # noqa: E402
import structured_source  # noqa: E402

envelope = []
for raw in request["lines"]:
    found = security_envelope.extract_security_envelope(raw)
    envelope.append(None if found is None else {"syslog": found[0].fields.get("syslog", {}), "start": found[1]})

rfc5424 = {}
for version in request["versions"]:
    head = "<34>" + version + " 2026-10-11T22:14:15Z host"
    strict = structured_source.extract_rfc5424(head + " app 123 ID47 - msg")
    rfc5424[version] = {
        "extract_rfc5424": strict is not None and strict[1] is not None,
        "extract_pair_envelope": security_pairs.extract_pair_envelope(head + " app 123 ID47 [a: 1 b: 2]") is not None,
        "short_rfc5424_json": generic_structural_poc._short_rfc5424_json(head + ' {"a":1}') is not None,
        "short_ietf_csv": security_envelope.extract_security_envelope(head + " 1,2,3") is not None,
        # The Generic Structural entry point must not let another grammar parse the line either.
        "parse_generic_structural": generic_structural_poc.parse_generic_structural(
            head + " app 123 ID47 - id=firewall sn=ABC fw=10.0.0.1 pri=6 src=10.1.1.1 dst=10.2.2.2").status == "SOURCE_PARSED",
    }

# key=value bodies go through the real preview entry point, the one the Analyze step calls.
kv = []
for raw in request.get("kvLines", []):
    result = multipass_preview_api.preview(raw)
    kv.append({"status": result["status"], "body": (result.get("fields") or {}).get("body") or {}})

# Standalone CEF/LEEF events, through the same preview entry point.
family = []
for item in request.get("familyLines", []):
    result = multipass_preview_api.preview(item["raw"])
    fields = result.get("fields") or {}
    family.append({"status": result["status"], "header": fields.get(item["family"] + "_header") or {},
                   "extension": fields.get(item["family"] + "_extension") or {}})

json.dump({"python": ".".join(map(str, sys.version_info[:3])), "envelope": envelope, "rfc5424": rfc5424, "kv": kv, "family": family}, sys.stdout)
