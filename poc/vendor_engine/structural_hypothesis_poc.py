"""Cross-event structural hypothesis PoC for security-product logs.

This module is intentionally isolated from the product parser.  It learns only
source-side structural evidence from a batch of samples: repeated key anchors,
delimiter choice, and anchor order.  Product/vendor names and semantic mappings
are not inputs to the learner.

The first PoC grammar is a bounded delimiter+KV hypothesis aimed at the class
that single-event heuristics handle conservatively: variable prefixes and
unquoted multi-word values that may themselves contain delimiter characters.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from math import ceil
import re
from typing import Iterable

from source_parse import SourceEvent, ValueSpan, assert_source_accounting

SAFE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_. /-]{0,63}")
KEY_AT = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9_. /-]{0,63}?)\s*=")
TOKEN = re.compile(r'"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\'|\S+')
MAX_TRAIN = 2048
MAX_ANCHORS = 96
MIN_TRAIN = 3


@dataclass(frozen=True)
class KeyMarker:
    key: str
    key_start: int
    eq_end: int
    delimiter_start: int | None


@dataclass(frozen=True)
class StructuralHypothesis:
    delimiter: str
    stable_anchors: tuple[str, ...]
    first_anchor: str | None
    min_anchor_hits: int
    terminal_anchors: tuple[str, ...]
    training_samples: int
    average_anchor_support: float
    order_consistency: float

    @property
    def confidence(self) -> float:
        return self.average_anchor_support * self.order_consistency


def _outside_delimiters(raw: str, delimiter: str) -> list[int]:
    positions: list[int] = []
    quote: str | None = None
    escaped = False
    for index, char in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            continue
        if char == delimiter:
            positions.append(index)
    return positions


def _delimiter_markers(raw: str, delimiter: str) -> list[KeyMarker]:
    markers: list[KeyMarker] = []
    for pos in _outside_delimiters(raw, delimiter):
        start = pos + 1
        while start < len(raw) and raw[start].isspace():
            start += 1
        match = KEY_AT.match(raw, start)
        if match is None:
            continue
        key = match.group("key").rstrip()
        if not SAFE_KEY.fullmatch(key):
            continue
        markers.append(KeyMarker(key, match.start("key"), match.end(), pos))
    return markers


def _first_segment_key_candidates(raw: str, delimiter: str) -> list[str]:
    positions = _outside_delimiters(raw, delimiter)
    end = positions[0] if positions else len(raw)
    segment = raw[:end]
    eq = segment.rfind("=")
    if eq <= 0:
        return []
    before = segment[:eq].rstrip()
    words = before.split()
    candidates: list[str] = []
    for width in range(1, min(5, len(words)) + 1):
        key = " ".join(words[-width:])
        if SAFE_KEY.fullmatch(key) and any(ch.isalpha() for ch in key):
            candidates.append(key)
    return candidates


def _find_first_anchor(raw: str, delimiter: str, key: str) -> KeyMarker | None:
    positions = _outside_delimiters(raw, delimiter)
    end = positions[0] if positions else len(raw)
    segment = raw[:end]
    pattern = re.compile(r"(?<![A-Za-z0-9_. /-])" + re.escape(key) + r"\s*=")
    matches = list(pattern.finditer(segment))
    if not matches:
        # The first key may follow an opaque variable-width prefix separated
        # only by whitespace.  Match the exact learned key at the segment tail.
        pattern = re.compile(re.escape(key) + r"\s*=")
        matches = list(pattern.finditer(segment))
    if not matches:
        return None
    match = matches[-1]
    return KeyMarker(key, match.start(), match.end(), None)


def _median_rank(sequences: list[list[str]], key: str) -> float:
    ranks = [seq.index(key) for seq in sequences if key in seq]
    if not ranks:
        return 10_000.0
    ranks.sort()
    middle = len(ranks) // 2
    return float(ranks[middle])


def _order_consistency(sequences: list[list[str]], ordered: list[str]) -> float:
    total = correct = 0
    rank = {key: index for index, key in enumerate(ordered)}
    for seq in sequences:
        seen = [rank[key] for key in seq if key in rank]
        for left, right in zip(seen, seen[1:]):
            total += 1
            if left < right:
                correct += 1
    return 1.0 if total == 0 else correct / total


def learn_delimited_kv_hypothesis(
    samples: Iterable[str], delimiter: str
) -> StructuralHypothesis | None:
    if delimiter not in (",", ";"):
        raise ValueError("HYPOTHESIS_DELIMITER_UNSUPPORTED")
    rows = [raw for raw in samples if isinstance(raw, str) and raw][:MAX_TRAIN]
    if len(rows) < MIN_TRAIN:
        return None

    sequences = [[m.key for m in _delimiter_markers(raw, delimiter)] for raw in rows]
    support = Counter(key for seq in sequences for key in set(seq))
    threshold = max(2, ceil(len(rows) * 0.50))
    stable = [key for key, count in support.items() if count >= threshold]
    stable.sort(key=lambda key: (_median_rank(sequences, key), key))
    stable = stable[:MAX_ANCHORS]

    # Completion needs end-of-record evidence, not only enough early anchors.
    # Learn a compact set of observed terminal keys covering most train rows.
    nonempty_sequences = [seq for seq in sequences if seq]
    terminal_counts = Counter(seq[-1] for seq in nonempty_sequences)
    terminal_anchors: list[str] = []
    terminal_covered = 0
    terminal_target = ceil(len(nonempty_sequences) * 0.80)
    for key, count in sorted(
        terminal_counts.items(), key=lambda item: (-item[1], item[0])
    ):
        if count < 2:
            continue
        terminal_anchors.append(key)
        terminal_covered += count
        if terminal_covered >= terminal_target or len(terminal_anchors) >= 8:
            break
    if not terminal_anchors or terminal_covered < max(2, ceil(len(nonempty_sequences) * 0.60)):
        return None

    first_support: Counter[str] = Counter()
    for raw in rows:
        # One sample votes once for each suffix candidate.
        first_support.update(set(_first_segment_key_candidates(raw, delimiter)))
    first_candidates = [
        (len(key.split()), len(key), key)
        for key, count in first_support.items()
        if count >= threshold and key not in stable
    ]
    first_anchor = max(first_candidates)[2] if first_candidates else None

    anchor_count = len(stable) + int(first_anchor is not None)
    if anchor_count < 3:
        return None

    avg_support = sum(support[key] / len(rows) for key in stable) / max(1, len(stable))
    if first_anchor is not None:
        avg_support = (
            avg_support * len(stable) + first_support[first_anchor] / len(rows)
        ) / anchor_count
    consistency = _order_consistency(sequences, stable)
    if consistency < 0.85:
        return None

    return StructuralHypothesis(
        delimiter=delimiter,
        stable_anchors=tuple(stable),
        first_anchor=first_anchor,
        min_anchor_hits=max(3, min(anchor_count, ceil(anchor_count * 0.60))),
        terminal_anchors=tuple(terminal_anchors),
        training_samples=len(rows),
        average_anchor_support=avg_support,
        order_consistency=consistency,
    )


def learn_best_hypothesis(samples: Iterable[str]) -> StructuralHypothesis | None:
    rows = list(samples)
    candidates = [
        item for item in (
            learn_delimited_kv_hypothesis(rows, ","),
            learn_delimited_kv_hypothesis(rows, ";"),
        ) if item is not None
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda item: (
            item.confidence,
            len(item.stable_anchors) + int(item.first_anchor is not None),
            item.training_samples,
        ),
    )


def _trim_value(raw: str, start: int, end: int) -> tuple[int, int]:
    while start < end and raw[start].isspace():
        start += 1
    while end > start and raw[end - 1].isspace():
        end -= 1
    if end - start >= 2 and raw[start] in ('"', "'") and raw[end - 1] == raw[start]:
        start += 1
        end -= 1
    return start, end


def _append_value(fields: dict[str, object], key: str, value: str) -> int:
    current = fields.get(key)
    if current is None:
        fields[key] = value
        return 0
    if isinstance(current, list):
        current.append(value)
        return len(current) - 1
    fields[key] = [current, value]
    return 1


def _prefix_tokens(raw: str, end: int) -> tuple[list[str], list[ValueSpan]]:
    values: list[str] = []
    spans: list[ValueSpan] = []
    prefix = raw[:end]
    for match in TOKEN.finditer(prefix):
        a, b = match.span()
        if b - a >= 2 and raw[a] in ('"', "'") and raw[b - 1] == raw[a]:
            a += 1
            b -= 1
        if a == b:
            continue
        values.append(raw[a:b])
        byte_a = len(raw[:a].encode("utf8"))
        byte_b = len(raw[:b].encode("utf8"))
        index = len(values) - 1
        spans.append(
            ValueSpan(
                f"hypothesis.prefix.{index}",
                byte_a,
                byte_b,
                ("hypothesis", "prefix_tokens", index),
            )
        )
    return values, spans


def parse_with_hypothesis(
    raw: str, hypothesis: StructuralHypothesis
) -> SourceEvent | None:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    if raw[:1] in ("{", "[") or raw.startswith(("CEF:", "LEEF:")):
        return None

    markers = _delimiter_markers(raw, hypothesis.delimiter)
    if hypothesis.first_anchor is not None:
        first = _find_first_anchor(raw, hypothesis.delimiter, hypothesis.first_anchor)
        if first is not None:
            markers.append(first)
    if not markers:
        return None
    markers.sort(key=lambda item: item.key_start)

    # Qualification uses only repeated training anchors.  Once qualified, all
    # syntactically valid key markers in the holdout are retained, including
    # previously unseen keys.
    learned = set(hypothesis.stable_anchors)
    if hypothesis.first_anchor is not None:
        learned.add(hypothesis.first_anchor)
    learned_hits = [marker for marker in markers if marker.key in learned]
    if len({marker.key for marker in learned_hits}) < hypothesis.min_anchor_hits:
        return None

    rank = {key: index for index, key in enumerate(hypothesis.stable_anchors)}
    observed = [rank[m.key] for m in markers if m.key in rank]
    if any(left >= right for left, right in zip(observed, observed[1:])):
        return None
    if markers[-1].key not in set(hypothesis.terminal_anchors):
        return None

    # Reject ambiguous duplicate marker starts and malformed empty keys.
    if len({marker.key_start for marker in markers}) != len(markers):
        return None

    first_field_start = markers[0].key_start
    prefix_values, prefix_spans = _prefix_tokens(raw, first_field_start)

    fields: dict[str, object] = {}
    spans = list(prefix_spans)
    for index, marker in enumerate(markers):
        value_end = (
            markers[index + 1].delimiter_start
            if index + 1 < len(markers)
            else len(raw)
        )
        if value_end is None:
            value_end = markers[index + 1].key_start
        value_start, value_end = _trim_value(raw, marker.eq_end, value_end)
        if value_end < value_start:
            return None
        value = raw[value_start:value_end]
        occurrence = _append_value(fields, marker.key, value)
        byte_a = len(raw[:value_start].encode("utf8"))
        byte_b = len(raw[:value_end].encode("utf8"))
        spans.append(
            ValueSpan(
                f"hypothesis.fields.{marker.key}",
                byte_a,
                byte_b,
                ("hypothesis", "fields", marker.key, occurrence),
            )
        )

    if len(fields) < 2:
        return None

    event = SourceEvent(raw, syntax="STRUCTURAL_HYPOTHESIS+DELIMITED_KV")
    event.vendor_fields = {
        "hypothesis": {
            "prefix_tokens": prefix_values,
            "fields": fields,
        }
    }
    event.value_spans = spans
    event.primitive_fields = len(spans)
    event.covered = [(0, len(raw))]
    assert_source_accounting(event)
    return event


def candidate_improves(baseline: SourceEvent, candidate: SourceEvent | None) -> bool:
    if candidate is None or candidate.status != "SOURCE_PARSED":
        return False
    if baseline.status == "SOURCE_PARSED" or baseline.raw != candidate.raw:
        return False
    return candidate.residual_bytes < baseline.residual_bytes


@dataclass(frozen=True)
class PositionalCsvHypothesis:
    width: int
    training_support: int
    eligible_training_events: int
    support_ratio: float


def _csv_width(event: SourceEvent) -> int:
    indexes: set[int] = set()
    for span in event.value_spans:
        match = re.search(r"(?:^|\.)column_(\d+)$", span.path)
        if match:
            indexes.add(int(match.group(1)))
    if not indexes:
        return 0
    if indexes != set(range(max(indexes) + 1)):
        return 0
    return len(indexes)


def learn_positional_csv_hypothesis(
    training_events: Iterable[SourceEvent],
) -> PositionalCsvHypothesis | None:
    eligible: list[int] = []
    for event in training_events:
        if event.status == "SOURCE_PARSED":
            continue
        if event.residual_bytes != 0:
            continue
        if set(event.issues) != {"UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION"}:
            continue
        width = _csv_width(event)
        if width >= 6:
            eligible.append(width)
    if len(eligible) < 3:
        return None
    counts = Counter(eligible)
    width, support = max(counts.items(), key=lambda item: (item[1], item[0]))
    ratio = support / len(eligible)
    if support < 3 or ratio < 0.80:
        return None
    return PositionalCsvHypothesis(
        width=width,
        training_support=support,
        eligible_training_events=len(eligible),
        support_ratio=ratio,
    )


def confirm_positional_csv(
    event: SourceEvent, hypothesis: PositionalCsvHypothesis | None
) -> SourceEvent | None:
    if hypothesis is None or event.status == "SOURCE_PARSED":
        return None
    if event.residual_bytes != 0:
        return None
    if set(event.issues) != {"UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION"}:
        return None
    if _csv_width(event) != hypothesis.width:
        return None
    from copy import deepcopy

    candidate = deepcopy(event)
    candidate.issues = []
    candidate.syntax += "+CORPUS_CONFIRMED_POSITIONAL"
    assert_source_accounting(candidate)
    if candidate.status != "SOURCE_PARSED":
        return None
    return candidate
