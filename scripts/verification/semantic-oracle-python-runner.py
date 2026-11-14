"""Runs the Python Multi-Pass header entry points for the Semantic Oracle.

Input (stdin, JSON):
  {"moduleDir": "<directory that holds the Multi-Pass modules>",
   "lines": ["<raw line>", ...],
   "kvLines": ["<raw line with a key=value body>", ...],
   "familyLines": [{"family": "cef" | "leef", "raw": "<raw line>"}, ...],
   "csvLines": ["<comma-separated row>", ...],
   "jsonLines": ["<JSON object event>", ...],
   "versions": ["1", "2", ...]}
Output (stdout, JSON):
  {"python": "<version>",
   "envelope": [null | {"syslog": {...}, "start": <payload offset>}, ...],
   "kv": [{"status": "<preview status>", "body": {<key>: <value> | [<values>]}}, ...],
   "family": [{"status": "<preview status>", "header": {...}, "extension": {...}}, ...],
   "csv": [{"candidate": bool, "values": [<field>, ...]}, ...],
   "json": [{"status": "<preview status>", "fields": {...}}, ...],
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

# Comma-separated rows. The preview offers a headerless row as a candidate (column_0, column_1, ...) that
# still needs corpus confirmation; a row it finds malformed is not offered.
csv_rows = []
for raw in request.get("csvLines", []):
    result = multipass_preview_api.preview(raw)
    fields = result.get("fields") or {}
    candidate = ("CSV_UNLABELED_CANDIDATE" in (result.get("syntax") or "")
                 and not any(issue.startswith("SOURCE_SYNTAX_ERROR") for issue in result.get("issues") or [])
                 and "column_0" in fields)
    values = []
    while candidate and ("column_%d" % len(values)) in fields:
        values.append(fields["column_%d" % len(values)])
    csv_rows.append({"candidate": candidate, "values": values})

# JSON object events. The oracle reads this output with a JavaScript JSON parser, which cannot hold an integer
# beyond 2^53 exactly; such an integer is handed over as its decimal digits so the comparison stays exact.
def exact(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and abs(value) > 2 ** 53 - 1:
        return str(value)
    if isinstance(value, dict):
        return {key: exact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [exact(item) for item in value]
    return value


json_events = []
for raw in request.get("jsonLines", []):
    result = multipass_preview_api.preview(raw)
    json_events.append({"status": result["status"], "fields": exact(result.get("fields") or {})})

json.dump({"python": ".".join(map(str, sys.version_info[:3])), "envelope": envelope, "rfc5424": rfc5424, "kv": kv, "family": family, "csv": csv_rows,
           "json": json_events}, sys.stdout)
