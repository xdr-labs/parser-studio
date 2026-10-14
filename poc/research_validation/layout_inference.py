"""H2r: bounded raw-only competing layout inference, independent of H3.

Learn delimiter, possible quoting interpretations and lexical column guards.
Keep the current engine first. Unknown quote meaning and source drift abstain.
Source strings and spans are preserved without Dictionary/type conversion.
Space layouts need at least two typed columns and four columns in total.
No metadata parsing, external acquisition, arbitrary regex or learned literals.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import ipaddress
from itertools import islice
import re
from typing import Callable, Iterable

from candidate import (MAX_TRAIN, MAX_RAW_BYTES, KEY, delimited_cells, _event)
from source_parse import SourceEvent

DELIMITERS = (',', '\t', ';', '|', ' ')
NUMBER = re.compile(r'[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\Z')
MAX_MODELS = 16


@dataclass(frozen=True)
class Layout:
    delimiter: str
    quotes: tuple[str, ...]
    width: int
    column_shapes: tuple[str | None, ...]
    train_sha256: tuple[str, ...]


def shape(value: str) -> str | None:
    if NUMBER.fullmatch(value):
        return 'number'
    if '.' in value or ':' in value:
        try:
            ipaddress.ip_address(value)
            return 'address'
        except ValueError:
            pass
    return None


def _cells(raw: str, delimiter: str, quote: str):
    cells = delimited_cells(raw, delimiter, quote)
    # Another quote cannot turn an unterminated leading quote into a literal.
    for _, start, end in cells:
        segment = raw[start:end]
        own_quote = start > 0 and raw[start-1:start] == quote and raw[end:end+1] == quote
        if not own_quote and segment[:1] in ('"', "'"):
            if len(segment) < 2 or segment[-1:] != segment[:1]:
                raise ValueError('LAYOUT_UNCLOSED_ALTERNATE_QUOTE')
    return cells


def _rows(samples: Iterable[str]) -> list[str]:
    rows = list(islice(samples, MAX_TRAIN + 1))
    if len(rows) > MAX_TRAIN:
        return []
    if any(not isinstance(r, str) or not r or len(r.encode('utf8')) > MAX_RAW_BYTES
           or '\x00' in r for r in rows):
        return []
    return list(dict.fromkeys(rows))


def fit_layout(samples: Iterable[str]) -> Layout | None:
    """Raw-only fit; no parameter can accept reference fields or vendor labels."""
    rows = _rows(samples)
    if len(rows) < 3:
        return None
    if any(KEY.match(r.lstrip()) or r.lstrip().startswith(('{', '[', '<', 'CEF:', 'LEEF:', '#'))
           for r in rows):
        return None
    candidates = []
    for delimiter in DELIMITERS:
        for quote in ('"', "'"):
            try:
                parsed = [_cells(r, delimiter, quote) for r in rows]
            except ValueError:
                continue
            width = len(parsed[0])
            if width < 2 or any(len(c) != width for c in parsed):
                continue
            column_shapes = []
            for column in range(width):
                kinds = {shape(c[column][0]) for c in parsed}
                column_shapes.append(next(iter(kinds)) if len(kinds) == 1 else None)
            typed = sum(s is not None for s in column_shapes)
            if not typed:
                continue
            if delimiter == ' ' and (typed < 2 or width < 4 or
                                      any(not value for cells in parsed for value, _, _ in cells)):
                continue
            quoted = sum(start > 0 and r[start-1:start] == quote and r[end:end+1] == quote
                         for r, cells in zip(rows, parsed) for _, start, end in cells)
            signature = tuple(tuple(cells) for cells in parsed)
            candidates.append(((typed, quoted), signature, delimiter, quote, width, tuple(column_shapes)))
    if not candidates:
        return None
    best_score = max(c[0] for c in candidates)
    best = [c for c in candidates if c[0] == best_score]
    if len({(c[1], c[2]) for c in best}) != 1:
        return None
    first = best[0]
    return Layout(first[2], tuple(dict.fromkeys(c[3] for c in best)), first[4], first[5],
                  tuple(sorted(hashlib.sha256(r.encode('utf8')).hexdigest() for r in rows)))


def fit_layouts(samples: Iterable[str]) -> tuple[Layout, ...]:
    """Bounded unlabeled width grouping; no per-vendor or semantic routing.

    A single homogeneous model is preferred. If it fails, only multi-sample
    delimiter/width groups which pass the full unambiguous fit are retained.
    A row may be eligible for several groups; prediction must still agree.
    """
    rows = _rows(samples)
    model = fit_layout(rows)
    if model is not None:
        return (model,)
    groups: dict[tuple[str, int], set[str]] = {}
    for raw in rows:
        for delimiter in DELIMITERS:
            for quote in ('"', "'"):
                try:
                    cells = _cells(raw, delimiter, quote)
                except ValueError:
                    continue
                if len(cells) >= 2:
                    groups.setdefault((delimiter, len(cells)), set()).add(raw)
    models = set()
    for (delimiter, _), group in groups.items():
        if len(group) < 3:
            continue
        fitted = fit_layout(sorted(group))
        if fitted is not None and fitted.delimiter == delimiter:
            models.add(fitted)
        if len(models) > MAX_MODELS:
            return ()
    return tuple(sorted(models, key=lambda m: (m.delimiter, m.width, m.quotes, m.train_sha256)))


def parse_with_layout(raw: str, model: Layout | tuple[Layout, ...] | None, *,
                      base_parser: Callable[[str], SourceEvent]) -> SourceEvent:
    primary = base_parser(raw)
    if not model:
        return primary
    if primary.syntax not in {'UNKNOWN', 'CSV_UNLABELED_CANDIDATE'}:
        return primary
    if primary.syntax == 'UNKNOWN' and primary.vendor_fields:
        return primary
    if not raw or len(raw.encode('utf8')) > MAX_RAW_BYTES or '\x00' in raw:
        return primary
    models = (model,) if isinstance(model, Layout) else model
    if len(models) > MAX_MODELS:
        return primary
    interpretations = {}
    for fitted in models:
        for quote in fitted.quotes:
            try:
                cells = _cells(raw, fitted.delimiter, quote)
            except ValueError:
                continue
            if len(cells) != fitted.width:
                continue
            shapes_match = all(kind is None or shape(cells[j][0]) == kind
                               for j, kind in enumerate(fitted.column_shapes))
            signature = tuple(cells)
            interpretations[signature] = interpretations.get(signature, False) or shapes_match
    # Equivalent quote dialects are kept until one original-byte parse remains.
    if len(interpretations) != 1:
        return primary
    cells = next(iter(interpretations))
    return _event(raw, 'INFERRED_LAYOUT',
                  [(f'column_{i}', value, a, b) for i, (value, a, b) in enumerate(cells)],
                  [(0, len(raw))], [] if interpretations[cells] else ['LAYOUT_COLUMN_SHAPE_DRIFT'])
