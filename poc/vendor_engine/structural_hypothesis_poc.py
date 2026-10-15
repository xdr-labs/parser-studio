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

from source_parse import SourceEvent, ValueSpan, _close, assert_source_accounting

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
    minimum_prefix_chars: int
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

    prefix_positions: list[int] = []
    for raw in rows:
        markers = _delimiter_markers(raw, delimiter)
        if first_anchor is not None:
            first = _find_first_anchor(raw, delimiter, first_anchor)
            if first is not None:
                markers.append(first)
        markers.sort(key=lambda item: item.key_start)
        if markers:
            prefix_positions.append(markers[0].key_start)
    if len(prefix_positions) < max(2, ceil(len(rows) * 0.60)):
        return None
    minimum_prefix_chars = min(prefix_positions)

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
        minimum_prefix_chars=minimum_prefix_chars,
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
    prefix_tolerance = max(
        4, min(24, ceil(hypothesis.minimum_prefix_chars * 0.15))
    )
    if markers[0].key_start < max(
        0, hypothesis.minimum_prefix_chars - prefix_tolerance
    ):
        return None

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


def _unparsed_byte_ranges(event: SourceEvent) -> list[tuple[int, int]]:
    raw = event.raw
    return [
        (
            len(raw[:start].encode("utf8")),
            len(raw[:end].encode("utf8")),
        )
        for start, end in event.unparsed
    ]


def merge_residual_hypothesis(
    baseline: SourceEvent, candidate: SourceEvent | None
) -> SourceEvent | None:
    """Preserve every baseline claim and add only values wholly inside residuals."""
    if candidate is None or candidate.status != "SOURCE_PARSED":
        return None
    if baseline.status == "SOURCE_PARSED" or baseline.raw != candidate.raw:
        return None
    hard_issue_fragments = (
        "SIZE_OR_NUL",
        "UNCLOSED",
        "TRUNCATED",
        "BYTE_LIMIT",
        "FIELD_LIMIT",
        "DEPTH_LIMIT",
        "INVALID",
    )
    if any(
        fragment in issue
        for issue in baseline.issues
        for fragment in hard_issue_fragments
    ):
        return None
    assert_source_accounting(baseline)
    assert_source_accounting(candidate)

    baseline_ranges = {
        (span.start_byte, span.end_byte)
        for span in baseline.value_spans
    }
    residual_ranges = _unparsed_byte_ranges(baseline)
    additions: list[ValueSpan] = []
    for span in candidate.value_spans:
        key = (span.start_byte, span.end_byte)
        if span.start_byte == span.end_byte:
            continue
        if key in baseline_ranges:
            continue
        if any(
            start <= span.start_byte and span.end_byte <= end
            for start, end in residual_ranges
        ):
            additions.append(span)
            continue
        # Every non-empty value claimed by the learned complete grammar must be
        # represented exactly by the baseline or be recoverable wholly from a
        # baseline residual.  Ignoring an overlapping/resegmented claim and
        # still declaring the event complete would be a false-complete path.
        return None
    if not additions:
        return None

    from copy import deepcopy

    result = deepcopy(baseline)
    residual_fields: dict[str, object] = {}
    replacement_spans: list[ValueSpan] = []
    raw_bytes = baseline.raw.encode("utf8")
    for index, span in enumerate(additions):
        key = f"value_{index}"
        value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
        residual_fields[key] = value
        replacement_spans.append(
            ValueSpan(
                f"hypothesis_residual.{key}",
                span.start_byte,
                span.end_byte,
                ("hypothesis_residual", key),
            )
        )

    result.vendor_fields = deepcopy(baseline.vendor_fields)
    result.vendor_fields["hypothesis_residual"] = residual_fields
    result.value_spans = list(baseline.value_spans) + replacement_spans
    result.primitive_fields = len(result.value_spans)
    result.syntax = baseline.syntax + "+STRUCTURAL_HYPOTHESIS_RESIDUAL"
    result.covered = [(0, len(result.raw))]
    result.unparsed = []
    result.issues = []
    assert_source_accounting(result)
    if result.status != "SOURCE_PARSED":
        return None
    return result


def candidate_improves(baseline: SourceEvent, candidate: SourceEvent | None) -> bool:
    return merge_residual_hypothesis(baseline, candidate) is not None


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


# ---------------------------------------------------------------------------
# Cross-event literal-anchor alignment hypothesis.
# ---------------------------------------------------------------------------

EVENT_CODE_CLUSTER = re.compile(
    r"%[A-Za-z0-9_-]+-(?:\d+)-(?P<message_id>\d+):"
)
TEMPLATE_LEX = re.compile(
    r"%[A-Za-z0-9_-]+-\d+-\d+:"
    r"|\"(?:\\.|[^\"])*\""
    r"|\'(?:\\.|[^\'])*\'"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|[A-Za-z_][A-Za-z0-9_.-]*"
    r"|\d+(?:\.\d+)*"
    r"|[^\w\s]"
)


@dataclass(frozen=True)
class TemplateToken:
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class GapRule:
    prefix: str
    suffix: str


@dataclass(frozen=True)
class EventTemplateHypothesis:
    message_id: str
    anchors: tuple[str, ...]
    gaps: tuple[GapRule, ...]
    training_support: int
    anchor_coverage: float
    minimum_terminal_fraction: float


def _event_message_id(raw: str) -> str | None:
    match = EVENT_CODE_CLUSTER.search(raw)
    return match.group("message_id") if match is not None else None


def _literal_tokens(raw: str) -> list[TemplateToken]:
    out: list[TemplateToken] = []
    for match in TEMPLATE_LEX.finditer(raw):
        text = match.group(0)
        if EVENT_CODE_CLUSTER.fullmatch(text):
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", text):
            continue
        out.append(TemplateToken(text, match.start(), match.end()))
    return out


def _lcs_tokens(left: list[str], right: list[str]) -> list[str]:
    if not left or not right:
        return []
    table = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for i, a in enumerate(left, 1):
        for j, b in enumerate(right, 1):
            table[i][j] = (
                table[i - 1][j - 1] + 1
                if a == b
                else max(table[i - 1][j], table[i][j - 1])
            )
    out: list[str] = []
    i, j = len(left), len(right)
    while i and j:
        if left[i - 1] == right[j - 1]:
            out.append(left[i - 1])
            i -= 1
            j -= 1
        elif table[i - 1][j] >= table[i][j - 1]:
            i -= 1
        else:
            j -= 1
    out.reverse()
    return out


def _match_anchor_positions(
    raw: str, anchors: tuple[str, ...] | list[str]
) -> list[TemplateToken] | None:
    tokens = _literal_tokens(raw)
    matched: list[TemplateToken] = []
    cursor = 0
    for anchor in anchors:
        found = None
        while cursor < len(tokens):
            token = tokens[cursor]
            cursor += 1
            if token.text == anchor:
                found = token
                break
        if found is None:
            return None
        matched.append(found)
    return matched


def _gap_ranges(raw: str, matched: list[TemplateToken]) -> list[tuple[int, int]]:
    if not matched:
        return []
    ranges = [(0, matched[0].start)]
    ranges.extend(
        (left.end, right.start)
        for left, right in zip(matched, matched[1:])
    )
    ranges.append((matched[-1].end, len(raw)))
    return ranges


def _common_prefix(values: list[str]) -> str:
    if not values:
        return ""
    prefix = min(values, key=len)
    while prefix and not all(value.startswith(prefix) for value in values):
        prefix = prefix[:-1]
    return prefix


def _common_suffix(values: list[str], prefix_length: int) -> str:
    if not values:
        return ""
    candidates = [value[prefix_length:] for value in values]
    suffix = min(candidates, key=len)
    while suffix and not all(value.endswith(suffix) for value in candidates):
        suffix = suffix[1:]
    return suffix


def _separator_prefix(value: str) -> str:
    match = re.match(r"^[^A-Za-z0-9_]*", value)
    return match.group(0) if match is not None else ""


def _separator_suffix(value: str) -> str:
    match = re.search(r"[^A-Za-z0-9_]*$", value)
    return match.group(0) if match is not None else ""


def _build_event_template(
    message_id: str, rows: list[str]
) -> EventTemplateHypothesis | None:
    if len(rows) < 2:
        return None
    literal_sequences = [[token.text for token in _literal_tokens(raw)] for raw in rows]
    common = list(literal_sequences[0])
    for sequence in literal_sequences[1:]:
        common = _lcs_tokens(common, sequence)
        if len(common) < 6:
            return None
    if len(common) < 6:
        return None

    coverage = sum(
        len(common) / max(1, len(sequence))
        for sequence in literal_sequences
    ) / len(literal_sequences)
    if coverage < 0.45:
        return None

    matched_rows: list[list[TemplateToken]] = []
    gap_rows: list[list[str]] = []
    terminal_fractions: list[float] = []
    for raw in rows:
        matched = _match_anchor_positions(raw, common)
        if matched is None:
            return None
        matched_rows.append(matched)
        ranges = _gap_ranges(raw, matched)
        gap_rows.append([raw[start:end] for start, end in ranges])
        terminal_fractions.append(matched[-1].end / max(1, len(raw)))

    if min(terminal_fractions) < 0.55:
        return None

    gap_rules: list[GapRule] = []
    for index in range(len(common) + 1):
        values = [gaps[index] for gaps in gap_rows]
        # Only boundary separators are grammar literals.  Alphanumeric common
        # prefixes/suffixes can be coincidentally constant source values
        # (addresses, users, IDs) and must remain variable slots.
        common_prefix = _common_prefix(values)
        prefix = _separator_prefix(common_prefix)
        common_suffix = _common_suffix(values, len(prefix))
        suffix = _separator_suffix(common_suffix)
        if prefix and suffix and all(
            len(value) < len(prefix) + len(suffix)
            for value in values
        ):
            suffix = ""
        gap_rules.append(GapRule(prefix, suffix))

    hypothesis = EventTemplateHypothesis(
        message_id=message_id,
        anchors=tuple(common),
        gaps=tuple(gap_rules),
        training_support=len(rows),
        anchor_coverage=coverage,
        minimum_terminal_fraction=min(terminal_fractions),
    )

    # Self-qualification: every train row must parse and obvious truncations
    # must fail closed before the hypothesis can be evaluated on holdout data.
    for raw in rows:
        candidate = parse_with_event_template(raw, {message_id: hypothesis})
        if candidate is None or candidate.status != "SOURCE_PARSED":
            return None
        mutations = [
            raw[: max(1, int(len(raw) * 0.60))],
            raw[: max(1, int(len(raw) * 0.80))],
            raw[max(1, int(len(raw) * 0.20)) :],
            raw[: max(1, len(raw) // 2)] + "\x00" + raw[len(raw) // 2 :],
        ]
        structural = delete_required_template_anchor(
            raw, {message_id: hypothesis}
        )
        if structural is not None:
            mutations.append(structural)
        for mutated in mutations:
            if parse_with_event_template(mutated, {message_id: hypothesis}) is not None:
                return None
    return hypothesis


def learn_event_template_hypotheses(
    samples: Iterable[str],
) -> dict[str, EventTemplateHypothesis]:
    groups: dict[str, list[str]] = defaultdict(list)
    for raw in list(samples)[:MAX_TRAIN]:
        if not isinstance(raw, str) or not raw:
            continue
        message_id = _event_message_id(raw)
        if message_id is not None:
            groups[message_id].append(raw)
    result: dict[str, EventTemplateHypothesis] = {}
    for message_id, rows in groups.items():
        hypothesis = _build_event_template(message_id, rows)
        if hypothesis is not None:
            result[message_id] = hypothesis
    return result


def parse_with_event_template(
    raw: str, hypotheses: dict[str, EventTemplateHypothesis]
) -> SourceEvent | None:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    if raw[:1] in ("{", "[") or raw.startswith(("CEF:", "LEEF:")):
        return None
    message_id = _event_message_id(raw)
    if message_id is None:
        return None
    hypothesis = hypotheses.get(message_id)
    if hypothesis is None:
        return None

    matched = _match_anchor_positions(raw, hypothesis.anchors)
    if matched is None:
        return None
    terminal_fraction = matched[-1].end / max(1, len(raw))
    if terminal_fraction < max(
        0.45, hypothesis.minimum_terminal_fraction - 0.12
    ):
        return None

    ranges = _gap_ranges(raw, matched)
    if len(ranges) != len(hypothesis.gaps):
        return None

    slots: list[str] = []
    spans: list[ValueSpan] = []
    for index, ((start, end), rule) in enumerate(zip(ranges, hypothesis.gaps)):
        text = raw[start:end]
        if not text.startswith(rule.prefix):
            return None
        if rule.suffix and not text.endswith(rule.suffix):
            return None
        center_start = start + len(rule.prefix)
        center_end = end - len(rule.suffix) if rule.suffix else end
        while center_start < center_end and raw[center_start].isspace():
            center_start += 1
        while center_end > center_start and raw[center_end - 1].isspace():
            center_end -= 1
        if center_start >= center_end:
            continue
        center = raw[center_start:center_end]
        if not any(char.isalnum() for char in center):
            continue
        slot_index = len(slots)
        slots.append(center)
        spans.append(
            ValueSpan(
                f"template.slot_{slot_index}",
                len(raw[:center_start].encode("utf8")),
                len(raw[:center_end].encode("utf8")),
                ("template", "slots", slot_index),
            )
        )
    if not slots:
        return None

    event = SourceEvent(raw, syntax="STRUCTURAL_HYPOTHESIS+EVENT_TEMPLATE")
    event.vendor_fields = {
        "template": {
            "message_id": message_id,
            "slots": slots,
        }
    }
    event.value_spans = spans
    event.primitive_fields = len(spans)
    event.covered = [(0, len(raw))]
    assert_source_accounting(event)
    return event


def delete_required_delimited_anchors(
    raw: str, hypothesis: StructuralHypothesis
) -> str | None:
    """Create a structural corruption by removing enough learned key anchors."""
    markers = _delimiter_markers(raw, hypothesis.delimiter)
    if hypothesis.first_anchor is not None:
        first = _find_first_anchor(raw, hypothesis.delimiter, hypothesis.first_anchor)
        if first is not None:
            markers.append(first)
    markers.sort(key=lambda item: item.key_start)
    learned = set(hypothesis.stable_anchors)
    if hypothesis.first_anchor is not None:
        learned.add(hypothesis.first_anchor)

    by_key: dict[str, KeyMarker] = {}
    for marker in markers:
        if marker.key in learned and marker.key not in by_key:
            by_key[marker.key] = marker
    distinct = list(by_key.values())
    if len(distinct) < hypothesis.min_anchor_hits:
        return None

    remove_count = max(
        1, len(distinct) - hypothesis.min_anchor_hits + 1
    )
    # Prefer central anchors so this is neither ordinary prefix nor tail
    # truncation; those are tested separately.
    center = len(distinct) // 2
    ordered = sorted(
        distinct,
        key=lambda marker: abs(distinct.index(marker) - center),
    )
    selected = ordered[:remove_count]
    ranges = sorted(
        (
            marker.delimiter_start
            if marker.delimiter_start is not None
            else marker.key_start,
            marker.eq_end,
        )
        for marker in selected
    )
    mutated = raw
    for start, end in reversed(ranges):
        mutated = mutated[:start] + mutated[end:]
    return mutated if mutated != raw else None


def delete_required_template_anchor(
    raw: str, hypotheses: dict[str, EventTemplateHypothesis]
) -> str | None:
    """Create a structural corruption by removing one required literal anchor."""
    message_id = _event_message_id(raw)
    if message_id is None:
        return None
    hypothesis = hypotheses.get(message_id)
    if hypothesis is None:
        return None
    matched = _match_anchor_positions(raw, hypothesis.anchors)
    if not matched:
        return None
    target = matched[len(matched) // 2]
    mutated = raw[:target.start] + raw[target.end:]
    return mutated if mutated != raw else None


# ---------------------------------------------------------------------------
# Relative R-gram residual hypotheses.
# ---------------------------------------------------------------------------

RGRAM_TOKEN = re.compile(
    r"https?://\S+"
    r"|www\.\S+"
    r"|<[^>\r\n]*>"
    r"|\"(?:\\.|[^\"])*\""
    r"|'(?:\\.|[^'])*'"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+"
    r"|[0-9a-fA-F]{20,}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d[0-9/:.\-]{4,}\d"
    r"|\d+(?:\.\d+)*"
    r"|[A-Za-z_][A-Za-z0-9_-]*"
    r"|[^\w\s]"
)
RGRAM_VAR = "<VAR>"
RGRAM_MAX_REGION_CHARS = 16384
RGRAM_MAX_TOKENS = 192
RGRAM_HARD_ISSUE_FRAGMENTS = (
    "SIZE_OR_NUL",
    "UNCLOSED",
    "TRUNCATED",
    "BYTE_LIMIT",
    "FIELD_LIMIT",
    "DEPTH_LIMIT",
    "INVALID",
)


@dataclass(frozen=True)
class RelativeRgramHypothesis:
    signature: tuple[str, ...]
    training_support: int
    literal_tokens: int
    variable_slots: int


@dataclass(frozen=True)
class RgramToken:
    signature: str
    start: int
    end: int


def _rgram_dynamic_span(text: str, match: re.Match[str]) -> tuple[int, int] | None:
    token = match.group(0)
    start, end = match.span()
    if len(token) >= 2 and token[0] in ('"', "'") and token[-1] == token[0]:
        return start + 1, end - 1
    if len(token) >= 2 and token[0] == "<" and token[-1] == ">":
        return start + 1, end - 1
    if token.startswith(("http://", "https://", "www.")):
        return start, end
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", token):
        return start, end
    if "@" in token and re.fullmatch(
        r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+", token
    ):
        return start, end
    if re.fullmatch(r"[0-9a-fA-F]{20,}", token):
        return start, end
    if re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        token,
    ):
        return start, end
    if re.fullmatch(r"\d[0-9/:.\-]{4,}\d", token):
        punctuation = {char for char in token if not char.isdigit()}
        if punctuation:
            return start, end
    if re.fullmatch(r"\d+(?:\.\d+)*", token):
        return start, end
    return None


def _rgram_tokens(text: str) -> list[RgramToken] | None:
    if not text or len(text) > RGRAM_MAX_REGION_CHARS or "\x00" in text:
        return None
    out: list[RgramToken] = []
    for match in RGRAM_TOKEN.finditer(text):
        dynamic = _rgram_dynamic_span(text, match)
        if dynamic is None:
            out.append(RgramToken(match.group(0), *match.span()))
        else:
            start, end = dynamic
            if start < end:
                out.append(RgramToken(RGRAM_VAR, start, end))
    if not out or len(out) > RGRAM_MAX_TOKENS:
        return None
    return out


def _single_residual(event: SourceEvent) -> tuple[int, int] | None:
    if event.status == "SOURCE_PARSED" or len(event.unparsed) != 1:
        return None
    if any(
        fragment in issue
        for issue in event.issues
        for fragment in RGRAM_HARD_ISSUE_FRAGMENTS
    ):
        return None
    start, end = event.unparsed[0]
    if not (0 <= start < end <= len(event.raw)):
        return None
    if end - start < 12 or end - start > RGRAM_MAX_REGION_CHARS:
        return None
    return start, end


def _rgram_signature(
    event: SourceEvent,
) -> tuple[tuple[str, ...], list[tuple[int, int]]] | None:
    region = _single_residual(event)
    if region is None:
        return None
    start, end = region
    tokens = _rgram_tokens(event.raw[start:end])
    if tokens is None:
        return None
    signature = tuple(token.signature for token in tokens)
    variable_spans = [
        (start + token.start, start + token.end)
        for token in tokens
        if token.signature == RGRAM_VAR
    ]
    return signature, variable_spans


def learn_relative_rgram_hypotheses(
    training_events: Iterable[SourceEvent],
    *,
    minimum_support: int = 3,
) -> dict[tuple[str, ...], RelativeRgramHypothesis]:
    if minimum_support < 3:
        raise ValueError("RGRAM_MINIMUM_SUPPORT_TOO_LOW")
    groups: dict[tuple[str, ...], int] = Counter()
    for event in list(training_events)[:MAX_TRAIN]:
        observed = _rgram_signature(event)
        if observed is None:
            continue
        signature, variable_spans = observed
        literal_tokens = sum(token != RGRAM_VAR for token in signature)
        if (
            literal_tokens < 5
            or not variable_spans
            or len(variable_spans) > 32
        ):
            continue
        groups[signature] += 1

    out: dict[tuple[str, ...], RelativeRgramHypothesis] = {}
    for signature, support in groups.items():
        if support < minimum_support:
            continue
        literal_tokens = sum(token != RGRAM_VAR for token in signature)
        variable_slots = sum(token == RGRAM_VAR for token in signature)
        out[signature] = RelativeRgramHypothesis(
            signature=signature,
            training_support=support,
            literal_tokens=literal_tokens,
            variable_slots=variable_slots,
        )
    return out


def parse_with_relative_rgram(
    raw: str,
    structural_view: SourceEvent,
    hypotheses: dict[tuple[str, ...], RelativeRgramHypothesis],
) -> SourceEvent | None:
    if (
        not isinstance(raw, str)
        or structural_view.raw != raw
        or raw[:1] in ("{", "[")
        or raw.startswith(("CEF:", "LEEF:"))
    ):
        return None
    observed = _rgram_signature(structural_view)
    if observed is None:
        return None
    signature, variable_spans = observed
    hypothesis = hypotheses.get(signature)
    if hypothesis is None or len(variable_spans) != hypothesis.variable_slots:
        return None

    fields: dict[str, str] = {}
    spans: list[ValueSpan] = []
    for index, (start, end) in enumerate(variable_spans):
        if not (0 <= start < end <= len(raw)):
            return None
        value = raw[start:end]
        if not value:
            return None
        key = f"slot_{index}"
        fields[key] = value
        spans.append(
            ValueSpan(
                f"rgram.{key}",
                len(raw[:start].encode("utf8")),
                len(raw[:end].encode("utf8")),
                ("rgram", "slots", index),
            )
        )
    if not spans:
        return None

    event = SourceEvent(raw, syntax="STRUCTURAL_HYPOTHESIS+RELATIVE_RGRAM")
    event.vendor_fields = {"rgram": {"slots": fields}}
    event.value_spans = spans
    event.primitive_fields = len(spans)
    event.covered = [(0, len(raw))]
    assert_source_accounting(event)
    return event


def delete_required_rgram_literal(
    raw: str,
    structural_view: SourceEvent,
    hypotheses: dict[tuple[str, ...], RelativeRgramHypothesis],
) -> str | None:
    observed = _rgram_signature(structural_view)
    if observed is None:
        return None
    signature, _variable_spans = observed
    if signature not in hypotheses:
        return None
    region = _single_residual(structural_view)
    if region is None:
        return None
    region_start, region_end = region
    tokens = _rgram_tokens(raw[region_start:region_end])
    if tokens is None:
        return None
    literals = [
        token for token in tokens if token.signature != RGRAM_VAR
    ]
    if len(literals) < 5:
        return None
    target = literals[len(literals) // 2]
    start = region_start + target.start
    end = region_start + target.end
    mutated = raw[:start] + raw[end:]
    return mutated if mutated != raw else None


# ---------------------------------------------------------------------------
# Cross-event aligned residual atoms.
# ---------------------------------------------------------------------------

ALIGNED_TIME_LIKE = re.compile(r"^\d[0-9/:.\-]{4,}\d$")
ALIGNED_ISO_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
)


@dataclass(frozen=True)
class AlignedResidualHypothesis:
    residual_count: int
    residual_index: int
    anchors: tuple[str, ...]
    typed_anchor_indexes: tuple[int, ...]
    training_support: int
    minimum_coverage: float


def _time_like_value(value: str) -> bool:
    if ALIGNED_ISO_DATETIME.fullmatch(value) is not None:
        return True
    if ALIGNED_TIME_LIKE.fullmatch(value) is None:
        return False
    punctuation = {char for char in value if not char.isdigit()}
    return ":" in punctuation and bool({"/", "-"} & punctuation)


def _match_rgram_anchors(
    tokens: list[RgramToken], anchors: tuple[str, ...] | list[str]
) -> list[RgramToken] | None:
    matched: list[RgramToken] = []
    cursor = 0
    for anchor in anchors:
        found = None
        while cursor < len(tokens):
            token = tokens[cursor]
            cursor += 1
            if token.signature == anchor:
                found = token
                break
        if found is None:
            return None
        matched.append(found)
    return matched


def learn_aligned_residual_hypotheses(
    training_events: Iterable[SourceEvent],
    *,
    minimum_support: int = 3,
) -> dict[tuple[int, int], AlignedResidualHypothesis]:
    """Learn repeated anchor subsequences per residual ordinal.

    This is deliberately a partial-recovery learner.  It does not claim that
    the entire event grammar is known.  Only strongly typed values occupying a
    stable cross-event anchor position can later be added to an incomplete
    event.
    """
    if minimum_support < 3:
        raise ValueError("ALIGNED_RESIDUAL_MINIMUM_SUPPORT_TOO_LOW")

    groups: dict[
        tuple[int, int],
        list[tuple[SourceEvent, int, int, list[RgramToken]]],
    ] = defaultdict(list)
    for event in list(training_events)[:MAX_TRAIN]:
        if event.status == "SOURCE_PARSED":
            continue
        if any(
            fragment in issue
            for issue in event.issues
            for fragment in RGRAM_HARD_ISSUE_FRAGMENTS
        ):
            continue
        residual_count = len(event.unparsed)
        if residual_count == 0:
            continue
        for index, (start, end) in enumerate(event.unparsed):
            if not (0 <= start < end <= len(event.raw)):
                continue
            if end - start < 12 or end - start > RGRAM_MAX_REGION_CHARS:
                continue
            tokens = _rgram_tokens(event.raw[start:end])
            if tokens:
                groups[(residual_count, index)].append(
                    (event, start, end, tokens)
                )

    result: dict[tuple[int, int], AlignedResidualHypothesis] = {}
    for key, rows in groups.items():
        if len(rows) < minimum_support:
            continue

        sequences = [
            [token.signature for token in tokens]
            for _event, _start, _end, tokens in rows
        ]
        common = list(sequences[0])
        for sequence in sequences[1:]:
            common = _lcs_tokens(common, sequence)
            if len(common) < 8:
                break
        if len(common) < 8:
            continue

        literal_tokens = sum(anchor != RGRAM_VAR for anchor in common)
        if literal_tokens < 5 or RGRAM_VAR not in common:
            continue

        coverages = [
            len(common) / max(1, len(sequence))
            for sequence in sequences
        ]
        minimum_coverage = min(coverages)
        if minimum_coverage < 0.55:
            continue

        typed_indexes: list[int] = []
        variable_indexes = [
            index for index, anchor in enumerate(common)
            if anchor == RGRAM_VAR
        ]
        for anchor_index in variable_indexes:
            typed_support = 0
            matched_rows = 0
            for event, start, _end, tokens in rows:
                matched = _match_rgram_anchors(tokens, common)
                if matched is None:
                    continue
                matched_rows += 1
                token = matched[anchor_index]
                value = event.raw[
                    start + token.start : start + token.end
                ]
                if _time_like_value(value):
                    typed_support += 1
            if (
                matched_rows >= minimum_support
                and typed_support == matched_rows
            ):
                typed_indexes.append(anchor_index)

        if not typed_indexes:
            continue

        residual_count, residual_index = key
        result[key] = AlignedResidualHypothesis(
            residual_count=residual_count,
            residual_index=residual_index,
            anchors=tuple(common),
            typed_anchor_indexes=tuple(typed_indexes),
            training_support=len(rows),
            minimum_coverage=minimum_coverage,
        )
    return result


def augment_with_aligned_residual_atoms(
    event: SourceEvent,
    hypotheses: dict[tuple[int, int], AlignedResidualHypothesis],
) -> SourceEvent:
    """Add cross-event qualified typed atoms while keeping incompleteness."""
    assert_source_accounting(event)
    if event.status == "SOURCE_PARSED" or not hypotheses:
        return event
    if any(
        fragment in issue
        for issue in event.issues
        for fragment in RGRAM_HARD_ISSUE_FRAGMENTS
    ):
        return event

    from copy import deepcopy

    out = deepcopy(event)
    existing = [
        (span.start_byte, span.end_byte)
        for span in out.value_spans
        if span.start_byte < span.end_byte
    ]
    bucket = list(
        out.vendor_fields.get("hypothesis_atoms", {}).get(
            "time_like", []
        )
    )
    additions: list[ValueSpan] = []
    added_char_ranges: list[tuple[int, int]] = []

    residual_count = len(event.unparsed)
    for index, (start, end) in enumerate(event.unparsed):
        hypothesis = hypotheses.get((residual_count, index))
        if hypothesis is None:
            continue
        tokens = _rgram_tokens(event.raw[start:end])
        if not tokens:
            continue
        # Holdout may contain longer free-text between the same exact
        # anchors. Keep every learned anchor mandatory, but allow bounded
        # additional prose without treating the train token ratio as a fixed
        # message length contract.
        minimum_holdout_coverage = max(
            0.55, hypothesis.minimum_coverage - 0.20
        )
        if (
            len(hypothesis.anchors) / max(1, len(tokens))
            < minimum_holdout_coverage
        ):
            continue
        matched = _match_rgram_anchors(
            tokens, hypothesis.anchors
        )
        if matched is None:
            continue

        for anchor_index in hypothesis.typed_anchor_indexes:
            token = matched[anchor_index]
            char_start = start + token.start
            char_end = start + token.end
            value = event.raw[char_start:char_end]
            if not _time_like_value(value):
                continue
            byte_start = len(
                event.raw[:char_start].encode("utf8")
            )
            byte_end = len(
                event.raw[:char_end].encode("utf8")
            )
            if any(
                max(byte_start, a) < min(byte_end, b)
                for a, b in existing
            ):
                continue
            if any(
                span.start_byte == byte_start
                and span.end_byte == byte_end
                for span in additions
            ):
                continue
            item_index = len(bucket)
            bucket.append(value)
            additions.append(
                ValueSpan(
                    f"hypothesis_atoms.time_like.{item_index}",
                    byte_start,
                    byte_end,
                    ("hypothesis_atoms", "time_like", item_index),
                )
            )
            added_char_ranges.append((char_start, char_end))

    if not additions:
        return event

    container = out.vendor_fields.get("hypothesis_atoms")
    if container is None:
        container = {}
        out.vendor_fields["hypothesis_atoms"] = container
    if not isinstance(container, dict):
        return event
    container["time_like"] = bucket

    out.value_spans.extend(additions)
    out.value_spans.sort(
        key=lambda span: (span.start_byte, span.end_byte, span.path)
    )
    out.primitive_fields = len(out.value_spans)
    out.covered.extend(added_char_ranges)
    out.syntax += "+ALIGNED_RESIDUAL_ATOMS"
    out.unparsed = []
    out = _close(out)
    # This layer improves recall only. It is never a completeness proof.
    if not out.issues:
        out.issues.append("ALIGNED_RESIDUAL_CANDIDATE_ONLY")
    assert_source_accounting(out)
    return out


def delete_required_aligned_anchor(
    raw: str,
    event: SourceEvent,
    hypotheses: dict[tuple[int, int], AlignedResidualHypothesis],
) -> str | None:
    """Delete one learned literal anchor for counterexample qualification."""
    if raw != event.raw:
        return None
    residual_count = len(event.unparsed)
    for index, (start, end) in enumerate(event.unparsed):
        hypothesis = hypotheses.get((residual_count, index))
        if hypothesis is None:
            continue
        tokens = _rgram_tokens(raw[start:end])
        if not tokens:
            continue
        matched = _match_rgram_anchors(tokens, hypothesis.anchors)
        if matched is None:
            continue
        literal_indexes = [
            anchor_index
            for anchor_index, anchor in enumerate(hypothesis.anchors)
            if anchor != RGRAM_VAR
        ]
        if len(literal_indexes) < 5:
            continue
        target_index = literal_indexes[len(literal_indexes) // 2]
        target = matched[target_index]
        char_start = start + target.start
        char_end = start + target.end
        mutated = raw[:char_start] + raw[char_end:]
        return mutated if mutated != raw else None
    return None
