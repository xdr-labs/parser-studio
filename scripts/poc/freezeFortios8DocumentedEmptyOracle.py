#!/usr/bin/env python3
"""Freeze manufacturer-authored FortiOS 8.0 custom Syslog examples and a
documented empty-marker contract BEFORE examining any parser candidate.

Private upstream source/extracted examples stay 0700/0600; only hash metadata
is committed. The docs are not authenticated device-captured wire telemetry.
"""
import hashlib
import html
import json
import os
import re
import urllib.request
from pathlib import Path

URL = "https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/779135"
PAGE_SHA = "b9ef7ca4e86f416415fa9c850fd738376f59a2808fa8f3ea289d3270a4d9bcd8"
PRIVATE = Path.home() / ".local/state/parserstudio-fortios8-empty-author-20261017"
PUBLIC = Path(__file__).with_name("fortios8EmptyPublisherManifest.pinned.json")
NAMES = ("eve_type", "eve_msg", "eve_vdom", "eve_level", "eve_status", "eve_profile")
# Independent source-byte locator derived exclusively from the author's
# declared template and HTML <pre> examples. Not a candidate parser.
LITERAL = re.compile(r'(?:^|[ \t])(eve_[a-z_]+)=("(?:[^"\\]|\\.)*"|[^ \t]+)')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def save(name, raw):
    fn = PRIVATE / name
    if fn.exists():
        if fn.read_bytes() != raw:
            raise ValueError("Immutable independently pinned author input drift: " + name)
        return
    fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out: out.write(raw)
def to_byte(raw, position): return len(raw[:position].encode("utf-8"))
def main():
    PRIVATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PRIVATE, 0o700)
    source = PRIVATE / "fortios8-custom-syslog-page.html"
    if source.exists():
        page = source.read_bytes()
    else:
        request = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            page = response.read()
    if sha(page) != PAGE_SHA:
        raise ValueError("Manufacturer document SHA drift: do not repin after candidate evaluation")
    save(source.name, page)
    data = page.decode("utf-8")
    # Manufacturer explicitly says that fields with empty values are displayed
    # with the custom configured '%' character, not the literal text '%'.
    if ("set empty-value-indicator" not in data or
        'fields with empty value display <code>%</code>' not in data or
        "eve_profile=$(profile)" not in data or "eve_status=$(status)" not in data):
        raise ValueError("Manufacturer configuration and expected semantics missing")
    candidates = [
        html.unescape(fragment.strip())
        for fragment in re.findall(r"<pre[^>]*>(.*?)</pre>", data, re.S)
        if "eve_profile=%" in fragment and "eve_type=" in fragment
    ]
    if len(candidates) != 2 or not all(x.startswith("Feb  2 16:") for x in candidates):
        raise ValueError("Manufacturer original example count/format changed")
    assert candidates[0] != candidates[1]
    rows = []
    by_name = {name:0 for name in NAMES}
    status_counts = {"PRESENT_EMPTY_DOCUMENTED":0,"PRESENT_NONEMPTY_LEXICAL":0}
    for index, raw in enumerate(candidates):
        found = []
        for match in LITERAL.finditer(raw):
            name = match.group(1)
            if name not in NAMES or name in [x["name"] for x in found]:
                raise ValueError("Manufacturer example has unsupported/duplicate field")
            lexeme = match.group(2)
            quoted = lexeme.startswith('"') and lexeme.endswith('"')
            if "\\" in lexeme:
                raise ValueError("Undocumented quoting/escape semantics in author example")
            state = "PRESENT_EMPTY_DOCUMENTED" if lexeme == "%" and not quoted else "PRESENT_NONEMPTY_LEXICAL"
            name_begin, name_end = match.span(1)
            value_begin, value_end = match.span(2)
            expected = {
                "name":name, "state":state, "rawLexeme":lexeme,
                "valueStartByte":to_byte(raw,value_begin),
                "valueEndByte":to_byte(raw,value_end),
                "nameStartByte":to_byte(raw,name_begin),
                "nameEndByte":to_byte(raw,name_end),
                "expectedDecodedEscape":"NOT_CERTIFIED",
                "expectedNullVsEmptyString":"UNSCORABLE",
            }
            if raw.encode("utf-8")[expected["valueStartByte"]:expected["valueEndByte"]].decode("utf-8") != lexeme:
                raise ValueError("Frozen UTF-8 source byte replay mismatch")
            found.append(expected)
            by_name[name] += 1
            status_counts[state] += 1
        if sorted(x["name"] for x in found) != sorted(NAMES):
            raise ValueError("Expected all six manufacturer-defined template fields")
        rows.append({
            "raw":raw,"rawSha256":sha(raw.encode("utf-8")),"manufacturerExampleIndex":index,
            "framingEvidence":"MANUFACTURER_FORTIOS_8_CUSTOM_SYSLOG_DOC",
            "profile":"CONFIGURED_UNQUOTED_PERCENT_EMPTY_MARKER",
            "expected":found,
            "authenticDeviceCapture":"NOT_VERIFIED",
            "nativeStellarParser":"NOT_VERIFIED",
        })
    if status_counts != {"PRESENT_EMPTY_DOCUMENTED":3,"PRESENT_NONEMPTY_LEXICAL":9}:
        raise ValueError("Unexpected manufacturer example status counts")
    data = (json.dumps(rows,ensure_ascii=False,separators=(",",":"),sort_keys=True)+"\n").encode("utf-8")
    save("manufacturer-empty-source-oracle.v1.json",data)
    manifest = {
        "pageUrl": URL, "manufacturer":"Fortinet",
        "version":"FortiOS 8.0.0",
        "mode":"custom Syslog KV with explicitly configured empty-value-indicator %",
        "sourcePageSha256":PAGE_SHA, "privateDocument":source.name,
        "privateOracle":"manufacturer-empty-source-oracle.v1.json",
        "oracleSha256":sha(data),"sourceExampleSha256":[x["rawSha256"] for x in rows],
        "sourceFieldNames":list(NAMES),
        "sourceExamples":len(rows),
        "referenceFields":sum(by_name.values()),
        "sourceReferenceStatusCounts":status_counts,
        "manufacturerMeaning":"empty marker indicates a present-but-empty source field only in configured custom mode",
        "limitations":["no authenticated device wire capture","no decoded escape oracle",
            "no empty string vs null type proof","no semantic proof outside documented custom config"],
        "rawOrExpectedValuesStoredInGit":False,
        "sourceDocumentLicense":"Fortinet copyrighted documentation; retained privately for evaluation only",
    }
    serialized = (json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode("utf-8")
    if PUBLIC.exists():
        if PUBLIC.read_bytes() != serialized: raise ValueError("Pinned manifest drift")
    else: PUBLIC.write_bytes(serialized)
    print(json.dumps({
        "status":"FROZEN_PRE_CANDIDATE_ORACLE","sourceSha":PAGE_SHA,
        "oracleSha":sha(data),"examples":len(rows),
        "expectedFields":sum(by_name.values()),"fieldStates":status_counts,
        "rawOrExpectedValuesPrinted":False,
    },sort_keys=True))
if __name__=="__main__": main()
