"""Runs the Python Multi-Pass header entry points for the Semantic Oracle.

Input (stdin, JSON):
  {"moduleDir": "<directory that holds the Multi-Pass modules>",
   "lines": ["<raw line>", ...],
   "versions": ["1", "2", ...]}
Output (stdout, JSON):
  {"python": "<version>",
   "envelope": [null | {"syslog": {...}, "start": <payload offset>}, ...],
   "rfc5424": {"<version>": {"extract_rfc5424": bool, "extract_pair_envelope": bool,
                             "short_rfc5424_json": bool, "short_ietf_csv": bool}}}

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
    }

json.dump({"python": ".".join(map(str, sys.version_info[:3])), "envelope": envelope, "rfc5424": rfc5424}, sys.stdout)
