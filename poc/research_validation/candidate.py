"""Independent, bounded source-extraction experiments. No normalization or IO.

H1: occurrence-preserving lexical KV, including fixed/empty/quoted values.
H2: raw-only multi-sample dialect selection; ambiguous candidates abstain.
H3: explicit source metadata, not guessed vendor semantics.
All input records and undecoded tails remain available. This module is NOT a
reproduction of DuckDB/CleverCSV/Datamaran or native Fluentd qualification.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
import hashlib
import re
import sys
from pathlib import Path
from typing import Iterable

BASE = Path(__file__).resolve().parents[1] / 'vendor_engine'
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
from source_parse import SourceEvent, ValueSpan, parse_source, _close
from engine import MAX_RAW_BYTES, PRI

MAX_FIELDS = 1024
MAX_TRAIN = 64
KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}=')
BAD_KEYS = {'__proto__', 'prototype', 'constructor'}


def byte_offsets(raw: str) -> list[int]:
    out = [0]
    for char in raw:
        out.append(out[-1] + len(char.encode('utf8')))
    return out


def _event(raw: str, syntax: str, cells: list[tuple[str, str, int, int]],
           covered: list[tuple[int, int]], issues: list[str]) -> SourceEvent:
    out = SourceEvent(raw, syntax=syntax)
    counts = Counter(k for k, _, _, _ in cells)
    occurrences: Counter[str] = Counter()
    offsets = byte_offsets(raw)
    for key, value, start, end in cells:
        if counts[key] > 1:
            out.vendor_fields.setdefault(key, []).append(value)
            path = f'{key}[{occurrences[key]}]'
        else:
            out.vendor_fields[key] = value
            path = key
        out.value_spans.append(ValueSpan(path, offsets[start], offsets[end]))
        occurrences[key] += 1
    out.primitive_fields = len(cells)
    out.covered = covered
    out.issues = issues
    return _close(out)


def lexical_kv(raw: str) -> SourceEvent | None:
    """Strict lexical dialect. No prose island or URL-query promotion."""
    offset = 0
    pri = PRI.match(raw)
    if pri and int(pri.group('priority')) <= 191:
        offset = pri.end()
    i = offset
    while i < len(raw) and raw[i].isspace():
        i += 1
    if not KEY.match(raw, i):
        return None
    cells: list[tuple[str, str, int, int]] = []
    covered = [(0, offset)] if offset else []
    issues: list[str] = []
    n = len(raw)
    while i < n:
        gap = i
        while i < n and raw[i].isspace():
            i += 1
        if i > gap:
            covered.append((gap, i))
        if i == n:
            break
        token_start = i
        match = KEY.match(raw, i)
        if not match or match.group()[:-1] in BAD_KEYS:
            issues.append('KV_UNRECOGNIZED_OR_UNSAFE_TOKEN')
            break
        if len(cells) >= MAX_FIELDS:
            issues.append('KV_FIELD_LIMIT')
            break
        key = match.group()[:-1]
        i = match.end()
        start = i
        if i < n and raw[i] in ('"', "'"):
            quote = raw[i]
            i += 1
            start = i
            decoded: list[str] = []
            while i < n and raw[i] != quote:
                if raw[i] == '\\' and i + 1 < n:
                    nxt = raw[i+1]
                    decoded.append(nxt if nxt in (quote, '\\') else raw[i:i+2])
                    i += 2
                else:
                    decoded.append(raw[i]); i += 1
            if i == n:
                issues.append('KV_UNCLOSED_QUOTE'); break
            end = i
            i += 1
            if i < n and not raw[i].isspace():
                issues.append('KV_INVALID_QUOTE_SUFFIX'); break
            value = ''.join(decoded)
        elif i < n and raw[i] in '[{':
            stack: list[str] = []
            quote = ''
            while i < n:
                char = raw[i]
                if quote:
                    if char == '\\' and i + 1 < n:
                        i += 2; continue
                    if char == quote:
                        quote = ''
                elif char in ('"', "'"):
                    quote = char
                elif char in '[{':
                    stack.append(']' if char == '[' else '}')
                    if len(stack) > 32:
                        issues.append('KV_CONTAINER_DEPTH'); break
                elif char in ']}':
                    if not stack or stack.pop() != char:
                        issues.append('KV_CONTAINER_MISMATCH'); break
                    if not stack:
                        i += 1; break
                i += 1
            if issues:
                break
            if stack or quote:
                issues.append('KV_UNCLOSED_CONTAINER'); break
            while i < n and not raw[i].isspace():
                i += 1
            end = i
            value = raw[start:end]
        else:
            while i < n and not raw[i].isspace():
                i += 1
            end = i
            value = raw[start:end]
        cells.append((key, value, start, end))
        covered.append((token_start, i))
    # Leading whitespace is syntax, not an unaccounted source gap.
    first = offset
    while first < n and raw[first].isspace():
        first += 1
    if first > offset:
        covered.append((offset, first))
    return _event(raw, 'LEXICAL_KV', cells, covered, issues)


@dataclass(frozen=True)
class Dialect:
    delimiter: str
    quote: str
    width: int
    train_sha256: tuple[str, ...]


def delimited_cells(raw: str, delimiter: str, quote: str = '"') -> list[tuple[str, int, int]]:
    """Independent span scanner; CSV doubled quoting only, no coercion."""
    out: list[tuple[str, int, int]] = []
    i = 0
    n = len(raw)
    while True:
        if len(out) >= MAX_FIELDS:
            raise ValueError('DELIMITED_FIELD_LIMIT')
        start = i
        if quote and i < n and raw[i] == quote:
            i += 1
            start = i
            parts: list[str] = []
            while i < n:
                if raw[i] == quote:
                    if i + 1 < n and raw[i+1] == quote:
                        parts.append(quote); i += 2; continue
                    break
                parts.append(raw[i]); i += 1
            if i == n:
                raise ValueError('DELIMITED_UNCLOSED_QUOTE')
            end = i
            value = ''.join(parts)
            i += 1
            if i < n and raw[i] != delimiter:
                raise ValueError('DELIMITED_QUOTE_SUFFIX')
        else:
            while i < n and raw[i] != delimiter:
                if raw[i] in '\r\n':
                    raise ValueError('DELIMITED_UNQUOTED_NEWLINE')
                i += 1
            end = i
            value = raw[start:end]
        out.append((value, start, end))
        if i == n:
            return out
        i += 1


def _typed(value: str) -> bool:
    return bool(re.fullmatch(r'[+-]?\d+(?:\.\d+)?', value) or
                re.fullmatch(r'\d{4}-\d\d-\d\d(?:[T ].*)?', value) or
                re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value))


def infer_dialect(samples: Iterable[str]) -> Dialect | None:
    """Fit on raw training only. No labels, heldout rows, vendor, or types IO."""
    rows = list(dict.fromkeys(samples))[:MAX_TRAIN]
    if len(rows) < 3 or any(not r or len(r.encode('utf8')) > MAX_RAW_BYTES or '\x00' in r for r in rows):
        return None
    if any(KEY.match(r.lstrip()) or r.lstrip().startswith(('{', '[', '<', 'CEF:', 'LEEF:')) for r in rows):
        return None
    options = []
    for delimiter in (',', '\t', ';', '|'):
        for quote in ('"', "'"):
            try:
                parsed = [delimited_cells(r, delimiter, quote) for r in rows]
            except ValueError:
                continue
            width = len(parsed[0])
            if width < 2 or any(len(c) != width for c in parsed):
                continue
            typed = sum(all(_typed(c[j][0]) for c in parsed) for j in range(width))
            if not typed:
                continue  # Do not certify arbitrary comma-containing prose.
            quoted = sum(r[a-1:a] == quote and r[b:b+1] == quote
                         for r, cells in zip(rows, parsed) for _, a, b in cells if a > 0)
            signature = tuple(tuple(c) for c in parsed)
            options.append(((typed, quoted), signature, delimiter, quote, width))
    if not options:
        return None
    top = max(o[0] for o in options)
    best = [o for o in options if o[0] == top]
    if len({(o[1], o[2]) for o in best}) != 1:
        return None
    _, _, delimiter, quote, width = best[0]
    hashes = tuple(sorted(hashlib.sha256(r.encode('utf8')).hexdigest() for r in rows))
    return Dialect(delimiter, quote, width, hashes)


def parse_candidate(raw: str, *, kv: bool = True, dialect: Dialect | None = None) -> SourceEvent:
    if not isinstance(raw, str):
        raise TypeError('RAW_NOT_STRING')
    if not raw or len(raw.encode('utf8')) > MAX_RAW_BYTES or '\x00' in raw:
        return parse_source(raw)
    if kv:
        event = lexical_kv(raw)
        if event is not None:
            return event
    if dialect is not None:
        try:
            cells = delimited_cells(raw, dialect.delimiter, dialect.quote)
            if len(cells) != dialect.width:
                raise ValueError('FROZEN_DIALECT_WIDTH_MISMATCH')
            return _event(raw, 'INFERRED_DELIMITED',
                          [(f'column_{i}', v, a, b) for i, (v, a, b) in enumerate(cells)],
                          [(0, len(raw))], [])
        except ValueError as exc:
            return _event(raw, 'INFERRED_DELIMITED', [], [], [str(exc)])
    return parse_source(raw)


@dataclass
class Document:
    records: list[str]
    events: list[tuple[int, SourceEvent]]
    metadata_indices: list[int]


def parse_document(records: list[str], *, metadata: bool = True, kv: bool = True,
                   dialect: Dialect | None = None) -> Document:
    """Zeek source header importer. Values remain raw scalar source strings.

    #types is used to validate schema width only. Sets, unset and empty-field
    tokens are preserved, not guessed or expanded. Metadata is retained apart
    from scored data rows, so no record disappears from the ledger.
    """
    if len(records) > 100000:
        raise ValueError('DOCUMENT_RECORD_LIMIT')
    result = Document(list(records), [], [])
    delimiter: str | None = None
    names: list[str] | None = None
    type_width: int | None = None
    for index, raw in enumerate(records):
        if not metadata:
            result.events.append((index, parse_candidate(raw, kv=kv, dialect=dialect)))
            continue
        if raw.startswith('#separator '):
            token = raw[len('#separator '):]
            delimiter = chr(int(token[2:], 16)) if re.fullmatch(r'\\x[0-9a-fA-F]{2}', token) else None
            if delimiter not in ('\t', ',', ';', '|'):
                delimiter = None
            names = None
            type_width = None
            result.metadata_indices.append(index)
            continue
        if delimiter is not None and raw.startswith('#'):
            if raw.startswith('#fields' + delimiter):
                proposed = raw.split(delimiter)[1:]
                names = proposed if (0 < len(proposed) <= MAX_FIELDS and len(set(proposed)) == len(proposed)
                    and all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}', n) and n not in BAD_KEYS for n in proposed)) else None
                type_width = None
            elif raw.startswith('#types' + delimiter):
                type_width = len(raw.split(delimiter)) - 1
            elif raw.startswith('#close'):
                names = None
                type_width = None
            result.metadata_indices.append(index)
            continue
        if delimiter is not None:
            if not names or type_width != len(names):
                event = _event(raw, 'DECLARED_DELIMITED', [], [], ['INVALID_OR_INCOMPLETE_SOURCE_SCHEMA'])
            elif not raw or len(raw.encode('utf8')) > MAX_RAW_BYTES or '\x00' in raw:
                event = parse_source(raw)
            else:
                # Zeek ASCII has no CSV quote escaping; literal quotes stay literal.
                try:
                    cells = delimited_cells(raw, delimiter, '')
                except ValueError as exc:
                    event = _event(raw, 'DECLARED_DELIMITED', [], [], [str(exc)])
                else:
                    if len(cells) != len(names):
                        event = _event(raw, 'DECLARED_DELIMITED', [], [], ['DECLARED_SCHEMA_WIDTH_MISMATCH'])
                    else:
                        event = _event(raw, 'DECLARED_DELIMITED',
                                       [(name, v, a, b) for name, (v, a, b) in zip(names, cells)],
                                       [(0, len(raw))], [])
            result.events.append((index, event))
        else:
            result.events.append((index, parse_candidate(raw, kv=kv, dialect=dialect)))
    assert len(result.events) + len(result.metadata_indices) == len(records)
    return result
