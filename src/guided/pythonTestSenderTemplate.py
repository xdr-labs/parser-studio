#!/usr/bin/env python3
"""Parser Studio synthetic test sender — user-run, stdlib-only.

The downloaded source embeds the browser sample in base64 (NOT encryption).
No connection is created until a user supplies a destination and types YES.
It never checks sensor ingestion or certifies target parser correctness.
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import io
import ipaddress
import json
import re
import secrets
import socket
import sys
import time

CONFIG_B64 = "__PARSER_STUDIO_CONFIG_B64__"
INTERVAL_SECONDS = 1.0
DEFAULT_SEND_COUNT = 60
MAX_SEND_COUNT = 600
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_ISO = re.compile(
    r"(?<!\d)(?P<date>\d{4}-\d{2}-\d{2})(?P<sep>[T ])"
    r"(?P<clock>\d{2}:\d{2}:\d{2})(?P<fraction>\.\d{1,9})?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})?(?!\d)"
)
_SLASH_DATE = re.compile(
    r"(?<!\d)\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?!\d)"
)
_RFC3164 = re.compile(
    rf"^(?P<pri><\d{{1,3}}>)?(?P<month>{_MONTH})"
    r"(?P<space> {1,2})(?P<day>\d{1,2}) (?P<clock>\d{2}:\d{2}:\d{2})"
)
_KV = re.compile(
    r"(?<![\w.])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})="
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s\t;,]+)"
)
_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_TIME_ONLY = re.compile(r"^\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$")
_EPOCH = re.compile(r"^\d{10}(?:\d{3}|\d{6}|\d{9})?$")
_IP_NAMES = frozenset((
    "src", "dst", "srcip", "dstip", "sourceip", "destinationip",
    "sourceaddress", "destinationaddress", "srcaddress", "dstaddress",
    "clientip", "serverip", "ip", "ipaddress", "localip", "remoteip",
    "srcipv6", "dstipv6", "sourceipv6", "destinationipv6",
))
_USER_NAMES = frozenset((
    "user", "username", "userid", "suser", "duser", "srcuser",
    "dstuser", "accountname", "principal", "login", "loginname",
))
_EMAIL_NAMES = frozenset((
    "email", "emailaddress", "mail", "mailaddress", "srcemail",
    "dstemail", "senderemail", "recipientemail", "useremail",
))
_LOCATION_NAMES = frozenset((
    "location", "city", "srccity", "dstcity", "region", "srcregion",
    "dstregion", "geolocation", "geo", "country", "srccountry",
    "dstcountry",
))
_TIME_NAMES = frozenset((
    "timestamp", "time", "eventtime", "generatedtime", "devtime",
    "receivetime", "datetime", "date", "start", "end", "rt",
))
_DOC_IPS = ("192.0.2.", "198.51.100.", "203.0.113.")
_CITIES = ("Seoul", "Tokyo", "London", "Toronto", "Paris", "Singapore")
_COUNTRIES = ("Korea", "Japan", "France", "Canada", "Singapore", "UnitedKingdom")


def _payload() -> dict:
    if CONFIG_B64.startswith("__PARSER_STUDIO"):
        raise RuntimeError("This template must be downloaded from Parser Studio.")
    payload = json.loads(base64.b64decode(CONFIG_B64, validate=True).decode("utf-8"))
    records = payload.get("events")
    if not isinstance(records, list) or not records or len(records) > 500:
        raise ValueError("Unsafe number of sample records.")
    if not all(isinstance(row, str) and row and len(row.encode("utf-8")) <= 65536
               for row in records):
        raise ValueError("Invalid sample record.")
    return payload


def _name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _ip(original: str) -> str:
    try:
        address = ipaddress.ip_address(original)
    except ValueError:
        return original
    if address.version == 6:
        value = int(ipaddress.IPv6Address("2001:db8::")) | secrets.randbits(96)
        return str(ipaddress.IPv6Address(value))
    for _attempt in range(5):
        candidate = secrets.choice(_DOC_IPS) + str(secrets.randbelow(253) + 1)
        if candidate != original:
            return candidate
    return "203.0.113.254" if original != "203.0.113.254" else "192.0.2.254"


def _email() -> str:
    return f"user{secrets.randbelow(1000000):06d}@example.test"


def _datetime_iso(match: re.Match[str]) -> str:
    old = match.group(0)
    try:
        parsed = dt.datetime.fromisoformat(old.replace("Z", "+00:00"))
    except ValueError:
        return old
    now = dt.datetime.now(parsed.tzinfo) if parsed.tzinfo else dt.datetime.now()
    fraction = match.group("fraction")
    precision = len(fraction) - 1 if fraction else 0
    zone = match.group("zone")
    stamp = now.strftime("%Y-%m-%d") + match.group("sep") + now.strftime("%H:%M:%S")
    if precision:
        stamp += "." + (f"{now.microsecond:06d}" + "000")[:precision]
    if zone == "Z":
        stamp += "Z"
    elif zone:
        stamp += now.strftime("%z")
        stamp = stamp[:-2] + ":" + stamp[-2:]
    return stamp


def _fresh_timestamps(source: str) -> str:
    now = dt.datetime.now()
    match = _RFC3164.match(source)
    if match:
        prefix = match.group("pri") or ""
        # RFC 3164 requires a space-padded single-digit day and one
        # separator before a two-digit day.
        replacement = prefix + now.strftime("%b") + f" {now.day:2d} " + now.strftime("%H:%M:%S")
        source = replacement + source[match.end():]
    source = _ISO.sub(_datetime_iso, source)
    source = _SLASH_DATE.sub(lambda _m: dt.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), source)
    return source


def _epoch_value(original: str) -> str:
    if not _EPOCH.fullmatch(original):
        return original
    length = len(original)
    now_ns = time.time_ns()
    return str(now_ns // (10 ** (19 - length))).zfill(length)


def _value_for_name(key: str, old: str) -> str:
    tag = _name(key)
    if tag in _IP_NAMES:
        return _ip(old)
    if tag in _EMAIL_NAMES:
        return _email()
    if tag in _USER_NAMES and old and old not in ("-", "null", "unknown"):
        return f"user{secrets.randbelow(100000):05d}"
    if tag in _LOCATION_NAMES or tag.endswith(("city", "country", "location")):
        options = _COUNTRIES if "country" in tag else _CITIES
        candidates = [name for name in options if name != old]
        return secrets.choice(candidates or options)
    if tag in _TIME_NAMES:
        if tag == "date" and re.fullmatch(r"\d{4}-\d{2}-\d{2}", old):
            return dt.datetime.now().strftime("%Y-%m-%d")
        if _EPOCH.fullmatch(old):
            return _epoch_value(old)
        if _TIME_ONLY.fullmatch(old):
            return dt.datetime.now().strftime("%H:%M:%S") + (
                "." + f"{dt.datetime.now().microsecond:06d}"[:len(old.split(".", 1)[1])]
                if "." in old else ""
            )
        if old == "" or old == "-":
            return old
        return _fresh_timestamps(old)
    return old


def _quoted(value: str, modified: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        # All generated test identities avoid quote, slash and whitespace.
        # Keep the same source quote style for CEF/KV lexical fidelity.
        return value[0] + modified + value[0]
    return modified


def _inline_fields(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        old = match.group("value")
        inside = old[1:-1] if len(old) >= 2 and old[0] == old[-1] and old[0] in "\"'" else old
        modified = _value_for_name(match.group("key"), inside)
        return match.group("key") + "=" + _quoted(old, modified)
    source = _KV.sub(replace, source)
    source = _EMAIL.sub(lambda _m: _email(), source)
    def ipv4(match: re.Match[str]) -> str:
        return _ip(match.group(0))
    source = _IPV4.sub(ipv4, source)
    return source


def _csv_segments(raw: str, delimiter: str) -> list[str] | None:
    parts: list[str] = []
    quoted = False
    start = 0
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == '"':
            if quoted and index + 1 < len(raw) and raw[index + 1] == '"':
                index += 2
                continue
            quoted = not quoted
        elif char == delimiter and not quoted:
            parts.append(raw[start:index])
            start = index + 1
        index += 1
    if quoted:
        return None
    parts.append(raw[start:])
    return parts


def _csv_event(source: str, columns: list[str], delimiter: str) -> str | None:
    segments = _csv_segments(source, delimiter)
    if segments is None or len(segments) != len(columns):
        return None
    try:
        rows = list(csv.reader(io.StringIO(source), delimiter=delimiter, strict=True))
    except csv.Error:
        return None
    if len(rows) != 1 or len(rows[0]) != len(columns):
        return None
    result: list[str] = []
    for name, old, lexical in zip(columns, rows[0], segments):
        updated = _value_for_name(name, old)
        updated = _fresh_timestamps(updated)
        updated = _EMAIL.sub(lambda _m: _email(), updated)
        updated = _IPV4.sub(lambda match: _ip(match.group(0)), updated)
        if updated == old:
            result.append(lexical)
        elif lexical.startswith('"') and lexical.endswith('"'):
            result.append('"' + updated.replace('"', '""') + '"')
        elif any(c in updated for c in (delimiter, '"', "\n", "\r")):
            result.append('"' + updated.replace('"', '""') + '"')
        else:
            result.append(updated)
    return delimiter.join(result)


def _json_event(source: str) -> str | None:
    try:
        parsed = json.loads(source)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None

    def walk(value: object, key: str = "", depth: int = 0) -> object:
        if depth > 16:
            return value
        if isinstance(value, dict):
            return {k: walk(v, k, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, key, depth + 1) for v in value]
        if isinstance(value, str):
            transformed = _fresh_timestamps(value)
            transformed = _value_for_name(key, transformed)
            transformed = _EMAIL.sub(lambda _m: _email(), transformed)
            transformed = _IPV4.sub(lambda match: _ip(match.group(0)), transformed)
            return transformed
        if isinstance(value, int) and _name(key) in _TIME_NAMES and not isinstance(value, bool):
            converted = _epoch_value(str(value))
            return int(converted) if converted != str(value) else value
        return value

    return json.dumps(walk(parsed), ensure_ascii=False, separators=(",", ":"))


def update_record(source: str, config: dict) -> str:
    fmt = config.get("format")
    if fmt == "json" or (fmt in ("auto", "mixed") and source.lstrip().startswith("{")):
        parsed = _json_event(source)
        if parsed is not None:
            return parsed
    if fmt == "csv" or (fmt in ("auto", "mixed") and
                        "=" not in source and not source.startswith(("<", "CEF:", "LEEF:"))):
        columns = config.get("csv_columns", [])
        delimiter = config.get("csv_delimiter", ",")
        if columns and delimiter in (",", ";", "\t"):
            csv_result = _csv_event(source, columns, delimiter)
            if csv_result is not None:
                return csv_result
    return _inline_fields(_fresh_timestamps(source))


def _destination() -> tuple[str, int, str, int, int]:
    print("This is a synthetic log sender. Run it only for a sensor you are authorized to test.")
    while True:
        target = input("Sensor IP address (IPv4 or IPv6): ").strip()
        try:
            address = ipaddress.ip_address(target)
            if address.is_unspecified or address.is_multicast:
                raise ValueError()
            break
        except ValueError:
            print("Enter a valid unicast IPv4 or IPv6 address.")
    while True:
        try:
            port = int(input("Sensor destination port (1–65535): ").strip())
            if 1 <= port <= 65535:
                break
        except ValueError:
            pass
        print("Port must be an integer from 1 to 65535.")
    while True:
        protocol = input("Transport [UDP/TCP] (default UDP): ").strip().upper() or "UDP"
        if protocol in ("UDP", "TCP"):
            break
        print("Choose UDP or TCP.")
    while True:
        raw = input(f"How many events [1-{MAX_SEND_COUNT}] (default {DEFAULT_SEND_COUNT}): ").strip()
        try:
            count = int(raw) if raw else DEFAULT_SEND_COUNT
            if 1 <= count <= MAX_SEND_COUNT:
                break
        except ValueError:
            pass
        print(f"Choose 1–{MAX_SEND_COUNT} events.")
    print(f"Destination: {address}:{port} / {protocol}, {count} event(s), 1 second apart.")
    print("The script's base64 sample is not encrypted. Unsupported fields may remain unchanged.")
    confirm = input("Type YES to start the authorized test: ").strip()
    if confirm != "YES":
        raise PermissionError("User did not approve network transmission.")
    return str(address), port, protocol, count, address.version


def main() -> int:
    try:
        config = _payload()
        host, port, protocol, count, ip_version = _destination()
    except (EOFError, KeyboardInterrupt, PermissionError) as exc:
        print(f"Stopped before sending: {exc}")
        return 1

    family = socket.AF_INET6 if ip_version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM)
    sent = 0
    try:
        sock.settimeout(5)
        if protocol == "TCP":
            sock.connect((host, port))
        records = config["events"]
        deadline = time.monotonic()
        for index in range(count):
            delay = deadline - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            raw = update_record(records[index % len(records)], config)
            message = raw.encode("utf-8")
            if protocol == "TCP":
                # Non-transparent LF framing (LF LF for explicitly grouped records).
                separator = b"\n\n" if config.get("event_boundary") == "blank-line" else b"\n"
                sock.sendall(message + separator)
            else:
                sock.sendto(message, (host, port))
            sent += 1
            print(f"Sent {sent}/{count} event(s) ({len(message)} bytes). Delivery is not verified.", flush=True)
            deadline += INTERVAL_SECONDS
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except (OSError, UnicodeError) as exc:
        print(f"Transport error after {sent} event(s): {exc}", file=sys.stderr)
        return 1
    finally:
        sock.close()
    print(f"Completed: attempted {sent} of {count} event(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
