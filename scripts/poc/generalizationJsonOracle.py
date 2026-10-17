#!/usr/bin/env python3
"""Independent byte-indexed JSON source oracle, not a Parser Studio parser.

Python's standard JSON decoder validates semantic values separately from this
byte-walking span scanner. A malformed, ambiguous or duplicate-key object is
UNSCORABLE, not evidence of a correct or incorrect vendor parser.
"""
import json
import re
from typing import Any

NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
WS = b" \r\n\t"
MAX_DEPTH = 20
MAX_FIELDS = 2000
MAX_RECORD_BYTES = 65536


class OracleInvalid(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise OracleInvalid("Non-JSON numeric constant")


def _no_unpaired_surrogate(value: Any) -> None:
    if isinstance(value, str):
        value.encode("utf-8", "strict")
    if isinstance(value, list):
        for child in value:
            _no_unpaired_surrogate(child)
    if isinstance(value, dict):
        for key, child in value.items():
            _no_unpaired_surrogate(key)
            _no_unpaired_surrogate(child)


class IndependentJsonByteOracle:
    def __init__(self, data: bytes, collect: bool = True) -> None:
        self.data = data
        self.pos = 0
        self.collect = collect
        self.fields: list[dict[str, Any]] = []
        self.top_array_elements: list[tuple[int, int]] = []

    def skip(self) -> None:
        while self.pos < len(self.data) and self.data[self.pos] in WS:
            self.pos += 1

    def take(self, expected: int) -> None:
        if self.pos >= len(self.data) or self.data[self.pos] != expected:
            raise OracleInvalid("Unexpected JSON delimiter")
        self.pos += 1

    def read_string(self) -> str:
        start = self.pos
        self.take(34)
        while self.pos < len(self.data):
            ch = self.data[self.pos]
            if ch == 34:
                self.pos += 1
                try:
                    result = json.loads(self.data[start:self.pos].decode("utf-8"))
                    _no_unpaired_surrogate(result)
                    return result
                except (ValueError, UnicodeError) as exc:
                    raise OracleInvalid("Invalid JSON string token") from exc
            if ch < 32:
                raise OracleInvalid("Raw control in JSON string")
            if ch == 92:
                self.pos += 2
            else:
                self.pos += 1
        raise OracleInvalid("Unterminated JSON string")

    def leaf(self, path: tuple[str, ...], value: Any, start: int) -> None:
        if not self.collect or not path:
            return
        if len(self.fields) >= MAX_FIELDS:
            raise OracleInvalid("Too many source leaf fields")
        typ = ("null" if value is None else "boolean" if isinstance(value, bool)
               else "integer" if isinstance(value, int) else "number"
               if isinstance(value, float) else "string")
        self.fields.append({
            "path": "/" + "/".join(path),
            "value": value,
            "type": typ,
            "value_start_byte": start,
            "value_end_byte": self.pos,
        })

    def value(self, path: tuple[str, ...] = (), depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise OracleInvalid("JSON nesting limit exceeded")
        self.skip()
        start = self.pos
        if start >= len(self.data):
            raise OracleInvalid("JSON value missing")
        token = self.data[start]
        if token == 123:
            self.pos += 1
            obj: dict[str, Any] = {}
            self.skip()
            if self.pos < len(self.data) and self.data[self.pos] == 125:
                self.pos += 1
                return obj
            while True:
                self.skip()
                if self.pos >= len(self.data) or self.data[self.pos] != 34:
                    raise OracleInvalid("JSON object field name missing")
                name = self.read_string()
                if name in obj:
                    raise OracleInvalid("Duplicate JSON object key")
                self.skip()
                self.take(58)
                key_path = name.replace("~", "~0").replace("/", "~1")
                obj[name] = self.value((*path, key_path), depth + 1)
                self.skip()
                if self.pos < len(self.data) and self.data[self.pos] == 125:
                    self.pos += 1
                    return obj
                self.take(44)
        if token == 91:
            self.pos += 1
            array: list[Any] = []
            self.skip()
            if self.pos < len(self.data) and self.data[self.pos] == 93:
                self.pos += 1
                return array
            while True:
                self.skip()
                element_start = self.pos
                array.append(self.value((*path, str(len(array))), depth + 1))
                if depth == 0:
                    self.top_array_elements.append((element_start, self.pos))
                self.skip()
                if self.pos < len(self.data) and self.data[self.pos] == 93:
                    self.pos += 1
                    return array
                self.take(44)
        if token == 34:
            result = self.read_string()
        elif self.data.startswith(b"true", self.pos):
            self.pos += 4
            result = True
        elif self.data.startswith(b"false", self.pos):
            self.pos += 5
            result = False
        elif self.data.startswith(b"null", self.pos):
            self.pos += 4
            result = None
        else:
            match = NUMBER.match(self.data, self.pos)
            if not match:
                raise OracleInvalid("Invalid JSON scalar token")
            self.pos = match.end()
            result = json.loads(match.group())
        self.leaf(path, result, start)
        return result

    def parse_complete(self) -> Any:
        if len(self.data) > 2 * 1024 * 1024:
            raise OracleInvalid("Oversized source file")
        result = self.value()
        self.skip()
        if self.pos != len(self.data):
            raise OracleInvalid("Trailing data after complete JSON")
        try:
            reference = json.loads(self.data.decode("utf-8"),
                                   parse_constant=_reject_constant)
            _no_unpaired_surrogate(reference)
        except (ValueError, UnicodeError) as exc:
            raise OracleInvalid("Independent canonical JSON failed") from exc
        if type(result) is not type(reference) or result != reference:
            raise OracleInvalid("Raw byte scanner and canonical JSON disagree")
        for leaf in self.fields:
            token = self.data[leaf["value_start_byte"]:leaf["value_end_byte"]]
            decoded = json.loads(token.decode("utf-8"))
            if type(decoded) is not type(leaf["value"]) or decoded != leaf["value"]:
                raise OracleInvalid("Source span does not replay to independent value")
        return result


def parse_json_event(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_RECORD_BYTES:
        raise OracleInvalid("JSON event exceeds per-event safety bound")
    parser = IndependentJsonByteOracle(raw)
    obj = parser.parse_complete()
    if not isinstance(obj, dict) or not parser.fields:
        raise OracleInvalid("Scorable event must contain named JSON object leaves")
    return parser.fields


def json_file_records(source: bytes) -> list[tuple[bytes, str]]:
    """Determine original events independently; keep source slices unchanged."""
    try:
        whole = IndependentJsonByteOracle(source, collect=False)
        obj = whole.parse_complete()
    except OracleInvalid:
        obj = None
    if isinstance(obj, list):
        return [(source[a:b], "json") for a, b in whole.top_array_elements]
    if isinstance(obj, dict):
        return [(source, "json")]
    # NDJSON is a physical-line format; do not silently glue invalid lines.
    return [(line, "json" if line.lstrip().startswith(b"{") else "unscorable")
            for line in source.splitlines() if line.strip()]
