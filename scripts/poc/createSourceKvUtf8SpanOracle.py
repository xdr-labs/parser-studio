#!/usr/bin/env python3
"""Independent byte-oriented KV source-span reference for frozen original events.

The private historical shlex field/value oracle is the external value authority.
This scanner does NOT consult the TypeScript lexer or product parser; its byte
offsets are half-open UTF-8 ranges in the entire unchanged original event.
A syntactically readable value is not manufacturer-certified.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

SOURCE = Path.home() / ".local/state/parserstudio-lossless-blind-20261017"
OUTPUT = Path.home() / ".local/state/parserstudio-source-kv-byte-span-20261017"
SOURCE_SHA = "153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32"
NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_.-]{0,127}")
PRI = re.compile(rb"<([0-9]{1,3})>[ \t]*")
RFC3164 = re.compile(
    rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +"
    rb"([0-3]?[0-9]) +([0-2][0-9]):([0-5][0-9]):([0-5][0-9]) +"
    rb"([^\s=]{1,253}) +"
)
HOST_LABEL = re.compile(rb"[A-Za-z0-9][A-Za-z0-9-]{0,61}")
BAD_NAMES = {"constructor", "__proto__", "prototype"}
CONTROL = frozenset((*range(9), *range(10, 32), 127))


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def start_after_envelope(data: bytes) -> tuple[int, str] | None:
    if not data or len(data) > 16384 or any(ch in CONTROL for ch in data):
        return None
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if data[0:1] == b"<":
        match = PRI.match(data)
        if match is None or int(match[1]) > 191:
            return None
        start, label = match.end(), "pri_kv"
    else:
        header = RFC3164.match(data)
        if header is not None:
            day, hour = int(header[2]), int(header[3])
            if not 1 <= day <= 31 or hour > 23:
                return None
            hostname = header[6]
            if not all(HOST_LABEL.fullmatch(part) for part in hostname.split(b".")):
                return None
            start, label = header.end(), "yearless_rfc3164_kv"
        else:
            start, label = 0, "bare_kv"
    first = NAME.match(data, start)
    if first is None or data[first.end():first.end() + 1] != b"=":
        return None
    return start, label


def decoded_value(raw_value: bytes) -> str | None:
    try:
        source = raw_value.decode("utf-8", errors="strict")
        if source.startswith('"'):
            if not source.endswith('"') or len(source) < 2:
                return None
            value = re.sub(r'\\(["\\])', r'\1', source[1:-1])
        elif source.startswith("'"):
            if not source.endswith("'") or len(source) < 2 or "\\" in source:
                return None
            value = source[1:-1]
        else:
            value = re.sub(r'\\(.)', r'\1', source, flags=re.DOTALL)
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            return None
        if len(value.encode("utf-8")) > 8192:
            return None
        return value
    except UnicodeDecodeError:
        return None


def scan_source(data: bytes) -> dict[str, object] | None:
    envelope = start_after_envelope(data)
    if envelope is None:
        return None
    start, kind = envelope
    cursor = start
    fields: list[dict[str, object]] = []
    seen: set[str] = set()
    while cursor < len(data):
        if data[cursor] in (32, 9):
            cursor += 1
            continue
        field_start = cursor
        name_match = NAME.match(data, cursor)
        if name_match is None or data[name_match.end():name_match.end() + 1] != b"=":
            return None
        name = data[cursor:name_match.end()].decode("ascii")
        canonical = name.replace("-", "_")
        if name in BAD_NAMES or canonical in seen:
            return None
        seen.add(canonical)
        cursor = name_match.end() + 1
        value_start = cursor
        quote = data[cursor] if cursor < len(data) and data[cursor] in (34, 39) else None
        if quote is not None:
            cursor += 1
            closed = False
            while cursor < len(data):
                ch = data[cursor]
                if ch == 92:
                    if cursor + 1 == len(data):
                        return None
                    cursor += 2
                elif ch == quote:
                    cursor += 1
                    closed = True
                    break
                else:
                    cursor += 1
            if not closed or (cursor < len(data) and data[cursor] not in (32, 9)):
                return None
        else:
            while cursor < len(data) and data[cursor] not in (32, 9):
                if data[cursor] in (34, 39):
                    return None
                if data[cursor] == 92:
                    if cursor + 1 == len(data):
                        return None
                    cursor += 2
                else:
                    cursor += 1
        raw_end = cursor
        value = decoded_value(data[value_start:raw_end])
        if value is None:
            return None
        fields.append({
            "name": name, "value": value,
            "rawStart": field_start, "rawEnd": raw_end,
            "nameStart": field_start, "nameEnd": name_match.end(),
            "valueStart": value_start, "valueEnd": raw_end,
        })
        if len(fields) > 256:
            return None
    if len(fields) < 2:
        return None
    for item in fields:
        a, b = int(item["rawStart"]), int(item["rawEnd"])
        n0, n1 = int(item["nameStart"]), int(item["nameEnd"])
        v0, v1 = int(item["valueStart"]), int(item["valueEnd"])
        if not (start <= a == n0 < n1 < v0 <= v1 == b <= len(data)):
            raise AssertionError("byte offsets violate field boundaries")
        if data[n0:n1].decode("ascii") != item["name"]:
            raise AssertionError("field name byte span does not round trip")
        if data[n1:v0] != b"=" or decoded_value(data[v0:v1]) != item["value"]:
            raise AssertionError("raw value byte span does not round trip")
    return {"envelope": kind, "prefixSha256": digest(data[:start]), "fields": fields}


def make_oracle() -> dict[str, object]:
    corpus = (SOURCE / "records.json").read_bytes()
    if digest(corpus) != SOURCE_SHA:
        raise ValueError("frozen source corpus SHA mismatch")
    records = json.loads(corpus)
    references = json.loads((SOURCE / "oracle-blind-syslog-kv-fields.json").read_bytes())
    if len(records) != 222 or len(references) != 185:
        raise ValueError("frozen source/reference denominator drift")
    result: dict[str, object] = {}
    counted = Counter()
    for item in records:
        ref = references.get(item["id"])
        if ref is None:
            continue
        original = item["raw"].encode("utf-8")
        sha = digest(original)
        if sha != ref["sourceSha256"]:
            raise ValueError("source identity conflict")
        lexical = scan_source(original)
        if lexical is None:
            result[item["id"]] = {"sourceSha256": sha, "status": "SOURCE_UNSCORABLE"}
            counted["unscorableEvents"] += 1
            continue
        expected = ref["fields"]
        fields = lexical["fields"]
        if len(fields) != len(expected) or ref["prefixHash"] != lexical["prefixSha256"]:
            result[item["id"]] = {"sourceSha256": sha, "status": "SOURCE_UNSCORABLE"}
            counted["unscorableEvents"] += 1
            continue
        semantic_conflicts = 0
        for source_field, (ref_name, ref_value) in zip(fields, expected):
            if source_field["name"] != ref_name:
                raise ValueError("frozen independent name oracle disagrees with byte boundary")
            source_field["referenceValue"] = ref_value
            qualified = source_field["value"] == ref_value
            source_field["referenceStatus"] = "SOURCE_QUALIFIED" if qualified else "VALUE_AMBIGUOUS"
            counted["byteSpanQualifiedFields"] += 1
            counted["sourceQualifiedFields"] += int(qualified)
            semantic_conflicts += int(not qualified)
        counted["semanticConflictFields"] += semantic_conflicts
        counted["sourceQualifiedEvents"] += semantic_conflicts == 0
        if semantic_conflicts:
            counted["sourcePartialEvents"] += 1
        result[item["id"]] = {
            "sourceSha256": sha, "sourceBytes": len(original),
            "family": ref["family"], "status":
                "SOURCE_PARTIAL" if semantic_conflicts else "SOURCE_QUALIFIED",
            "envelope": lexical["envelope"],
            "prefixSha256": lexical["prefixSha256"], "fields": fields,
        }
    if len(result) != 185 or counted["byteSpanQualifiedFields"] != 4160:
        raise AssertionError("frozen original field/span denominator drifted")
    return {
        "schemaVersion": 1, "frozenCorpusSha256": SOURCE_SHA, "records": result,
        "counts": dict(counted), "status": "POC_SOURCE_SPANS_ONLY",
        "manufacturerSemantics": "NOT_CERTIFIED", "nativeParser": "NOT_VERIFIED",
    }


def main() -> None:
    os.umask(0o077)
    result = make_oracle()
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    private = OUTPUT / "source-kv-utf8-byte-span-oracle.json"
    content = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if private.exists():
        if private.read_bytes() != content:
            raise ValueError("refusing to rewrite existing private byte-span oracle")
    else:
        descriptor = os.open(private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(content)
    if private.stat().st_mode & 0o077:
        raise PermissionError("private byte-span oracle permissions are not 0600")
    print("SOURCE_KV_INDEPENDENT_BYTE_SPAN_ORACLE " + json.dumps({
        "frozenCorpusSha256": SOURCE_SHA, "events": len(result["records"]),
        **result["counts"], "rawOrFieldValuesPrinted": False,
        "manufacturerSemantics": "NOT_CERTIFIED",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
