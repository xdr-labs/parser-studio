#!/usr/bin/env python3
"""Freeze independent generic CSV source-byte expectations before TypeScript candidate exists.

These are synthetic author-controlled records, not manufacturer or native-device goldens.
Python's csv module checks decoded cells; a separately written lexical scanner
accounts for physical UTF-8 source spans and quoted RFC 4180 bytes.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "scripts/poc/accE3E5DeclaredCsvOracle.pinned.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cells_from_python(row: str):
    result = list(csv.reader(io.StringIO(row), strict=True))
    if len(result) != 1:
        raise ValueError("not one CSV source row")
    starts = []
    start = 0
    quoted = False
    index = 0
    while index < len(row):
        if row[index] == '"':
            if quoted and index + 1 < len(row) and row[index + 1] == '"':
                index += 2
                continue
            quoted = not quoted
        elif row[index] == "," and not quoted:
            starts.append((start, index))
            start = index + 1
        index += 1
    if quoted:
        raise ValueError("unclosed quoted value")
    starts.append((start, len(row)))
    if len(starts) != len(result[0]):
        raise ValueError("independent csv span and decoder disagreement")
    decoded = result[0]
    for (a, b), val in zip(starts, decoded):
        lexical = row[a:b]
        if lexical.startswith('"') and lexical.endswith('"'):
            observed = lexical[1:-1].replace('""', '"')
        else:
            observed = lexical
        if observed != val:
            raise ValueError("independent decoded CSV value disagreement")
    return starts, decoded


def create(case_id: str, prefix: str, row: str, suffix: str, names: list[str],
           disposition="REVIEW_ONLY_EXTERNAL_CSV_SCHEMA", mutate="none"):
    source = prefix + row + suffix
    start = len(prefix.encode("utf-8"))
    end = len((prefix + row).encode("utf-8"))
    source_bytes = source.encode("utf-8")
    source_sha = sha(source_bytes)
    slice_sha = sha(row.encode("utf-8"))
    schema_sha = sha(json.dumps(names, ensure_ascii=False,
                                separators=(",", ":")).encode("utf-8"))
    expected = []
    if disposition == "REVIEW_ONLY_EXTERNAL_CSV_SCHEMA":
        ranges, values = cells_from_python(row)
        if len(ranges) != len(names):
            raise ValueError(f"{case_id}: wrong source header width")
        for i, ((a, b), value) in enumerate(zip(ranges, values)):
            begin = start + len(row[:a].encode("utf-8"))
            finish = start + len(row[:b].encode("utf-8"))
            lexical = source_bytes[begin:finish].decode("utf-8")
            expected.append(dict(ordinal=i, name=names[i], source_value=value,
                                 source_value_lexeme=lexical,
                                 start_byte=begin, end_byte=finish))
    return dict(case_id=case_id, source=source, start_byte=start,
                end_byte=end, source_sha256=source_sha, slice_sha256=slice_sha,
                ordered_names=names, ordered_names_sha256=schema_sha,
                record_framing="EXPLICIT_SINGLE_DISPLAYED_RECORD",
                declared_format="rfc4180_comma_csv",
                schema_provenance="PUBLISHER_DOCUMENTED_ORDER",
                mutate=mutate, expected_disposition=disposition, expected=expected)


cases = [
    create("bare_seven", "", "deny,10,192.0.2.8,00:10:8B:A7:EF:AA,IPS Sensor,214,signature", "",
           ["action", "severity", "source_ip", "source_mac", "component", "rule_id", "signature"]),
    create("declared_syslog_prefix", "<190>Oct 18 12:30:03 fw01 ",
           '1,2026/10/18 12:30:03,000123,TRAFFIC,end', "",
           ["sequence", "receive_time", "serial", "event_type", "subtype"]),
    create("reporter_prefix_and_unreviewed_suffix", "Receiver: <190>Oct 18 fw ",
           "allow,3,198.51.100.1", " [relay footer]",
           ["action", "severity", "source_ip"]),
    create("utf8_supplementary_value", "forwarder 🔥 ",
           'a,"source 😀 value",z', " tail", ["first", "details", "last"]),
    create("quoted_comma", "", 'a,"exact, quoted cell",z', "",
           ["first", "details", "last"]),
    create("escaped_double_quotes", "", 'a,"say ""hello""",z', "",
           ["first", "details", "last"]),
    create("empty_unquoted_value", "", 'a,,z', "", ["first", "middle", "last"]),
    create("empty_quoted_value", "", 'a,"",z', "", ["first", "middle", "last"]),
    create("one_column", "", "source", "", ["value"]),
    create("source_values_repeat_distinct_names", "", "a,a,a", "",
           ["first", "second", "third"]),
    create("string_numeric_and_bool_lexemes", "", "000123,0,false", "",
           ["incident_id", "risk", "enabled"]),
    create("unreviewed_named_prefix_stays_residual", "trace_id=not_scored ",
           "x,y", "", ["first", "second"]),
    create("newline_only_within_quoted_field", "",
           'deny,"first\nsecond",review', "", ["action", "description", "state"]),
]
base = ("", "a,b,c", "", ["first", "second", "third"])
negative = [
    ("framing_unconfirmed", "no_framing", base),
    ("wrong_source_sha", "bad_source_sha", base),
    ("wrong_source_slice_sha", "bad_slice_sha", base),
    ("wrong_schema_sha", "bad_schema_sha", base),
    ("invalid_source_offset", "negative_start", base),
    ("mid_codepoint_slice", "mid_utf8", ("prefix 😀 ", "a,b", "", ["first", "second"])),
    ("out_of_range_slice", "end_out_of_range", base),
    ("empty_slice", "empty_slice", base),
    ("wrong_declared_format", "wrong_format", base),
    ("unsupported_schema_provenance", "wrong_provenance", base),
    ("duplicate_schema_name", "none", ("", "a,b,c", "", ["field", "Field", "third"])),
    ("unsafe_schema_name", "none", ("", "a,b,c", "", ["first", "__proto__", "third"])),
    ("malformed_schema_name", "none", ("", "a,b,c", "", ["first", "has space", "third"])),
    ("schema_width_mismatch", "none", ("", "a,b,c", "", ["first", "third"])),
    ("missing_schema_columns", "none", ("", "a,b,c", "", [])),
    ("unclosed_quote", "none", ("", 'a,"missing,z', "", ["first", "second", "third"])),
    ("quote_mid_unquoted", "none", ("", 'a,abc"def,z', "", ["first", "second", "third"])),
    ("extra_record_line", "none", ("", "a,b,c\nd,e,f", "",
                                   ["first", "second", "third"])),
    ("embedded_nul", "none", ("", "a,\x00,c", "",
                               ["first", "second", "third"])),
    ("oversized_source", "oversized_source", base),
    ("oversized_slice", "oversized_slice", base),
    ("oversized_schema", "oversized_schema", base),
    ("invalid_utf8_bytes", "invalid_utf8", base),
    ("utf8_bom_source", "none", ("\ufeff", "a,b,c", "",
                                ["first", "second", "third"])),
]
for case_id, mutate, (prefix, row, suffix, names) in negative:
    cases.append(create(case_id, prefix, row, suffix, names,
                        disposition="RAW_ONLY" if mutate == "no_framing" else "ABSTAIN_UNSAFE",
                        mutate=mutate))

fixture = dict(schema_version="independent_synthetic_source_v1",
               evidence="AUTHOR_SYNTHETIC_NOT_DEVICE_OR_NATIVE",
               cases=cases)
output = (json.dumps(fixture, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
DEST.write_bytes(output)
print(f"ORACLE_SHA256={sha(output)} SYNTHETIC_CASES={len(cases)} "
      f"VALID={sum(bool(c['expected']) for c in cases)} "
      f"NEGATIVE={sum(not c['expected'] for c in cases)} "
      f"FIELDS={sum(len(c['expected']) for c in cases)}")
