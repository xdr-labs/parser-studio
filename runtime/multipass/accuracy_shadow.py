"""Offline, non-authoritative candidate accuracy research.

Never imported by product parsing, preview, authoring or runtime entry points.
A syntactically valid source span is not proof of the correct field name,
boundary, value or semantic role. MDL-inspired ranks are hypotheses only.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
from math import log2
from typing import Any, Iterable

from multipass_contract import CandidateResult


@dataclass(frozen=True)
class SpanAudit:
    valid: bool
    errors: tuple[str, ...]
    raw_lexeme_matches: int
    json_decoded_matches: int
    decoding_unverified: int


@dataclass(frozen=True)
class ShadowScore:
    valid: bool
    description_bits: float | None
    errors: tuple[str, ...]
    new_claims: int
    decoding_unverified: int


@dataclass(frozen=True)
class ShadowDecision:
    selected_index: int | None
    scores: tuple[ShadowScore, ...]
    baseline_preserved: bool


def _claim_key(occurrence: Any) -> tuple[Any, ...]:
    """Exact source-backed claim; typed values distinguish '1' from 1."""
    return (
        occurrence.display_path,
        occurrence.source_segments,
        occurrence.occurrence,
        type(occurrence.value).__name__,
        json.dumps(occurrence.value, sort_keys=True, ensure_ascii=False),
        occurrence.start_byte,
        occurrence.end_byte,
    )


def _ancestor(left: Any, right: Any) -> bool:
    a, b = left.source_segments, right.source_segments
    if a is not None and b is not None:
        return len(a) < len(b) and a == b[:len(a)]
    return right.display_path.startswith(left.display_path + ".")


def _overlap(a: Any, b: Any) -> bool:
    return max(a.start_byte, b.start_byte) < min(a.end_byte, b.end_byte)


def _valid_nested_overlap(a: Any, b: Any) -> bool:
    return (
        (_ancestor(a, b) and a.start_byte <= b.start_byte and b.end_byte <= a.end_byte)
        or (_ancestor(b, a) and b.start_byte <= a.start_byte and a.end_byte <= b.end_byte)
    )


def audit_candidate(
    raw: str, candidate: CandidateResult, baseline: CandidateResult | None = None
) -> SpanAudit:
    """Check hard source invariants without claiming semantic correctness.

    Valid escaped/decoded fields may not equal their original UTF-8 lexeme.
    An unknown decoder is recorded as UNVERIFIED, not rejected or certified.
    """
    source = raw.encode("utf8")
    errors: list[str] = []
    exact = decoded = unresolved = 0

    if candidate.raw_sha256 != sha256(source).hexdigest() or candidate.source_bytes != len(source):
        errors.append("SOURCE_IDENTITY_MISMATCH")
    if baseline is not None:
        if baseline.raw_sha256 != candidate.raw_sha256 or baseline.source_bytes != candidate.source_bytes:
            errors.append("BASELINE_SOURCE_IDENTITY_MISMATCH")
        if not Counter(map(_claim_key, baseline.occurrences)) <= Counter(
            map(_claim_key, candidate.occurrences)
        ):
            errors.append("BASELINE_CLAIMS_LOST")
        if baseline.completeness == "SOURCE_PARSED" and Counter(
            map(_claim_key, baseline.occurrences)
        ) != Counter(map(_claim_key, candidate.occurrences)):
            errors.append("COMPLETE_BASELINE_REINTERPRETED")

    covered = bytearray(len(source))
    for region in (*candidate.covered_regions, *candidate.residual_regions):
        a, b = region.start_byte, region.end_byte
        if not (0 <= a <= b <= len(source)):
            errors.append("SOURCE_ACCOUNTING_RANGE_INVALID")
            continue
        try:
            source[:a].decode("utf8")
            source[:b].decode("utf8")
        except UnicodeDecodeError:
            errors.append("SOURCE_ACCOUNTING_UTF8_BOUNDARY_INVALID")
            continue
        covered[a:b] = bytes([1]) * (b - a)
    if 0 in covered:
        errors.append("SOURCE_BYTES_NOT_ACCOUNTED")

    for occurrence in candidate.occurrences:
        a, b = occurrence.start_byte, occurrence.end_byte
        if not occurrence.display_path or a < 0 or b < a or b > len(source):
            errors.append("FIELD_SPAN_INVALID")
            continue
        try:
            source[:a].decode("utf8")
            lexeme = source[a:b].decode("utf8")
            source[:b].decode("utf8")
        except UnicodeDecodeError:
            errors.append("FIELD_UTF8_BOUNDARY_INVALID")
            continue
        if isinstance(occurrence.value, str) and lexeme == occurrence.value:
            exact += 1
        else:
            # JSON encoding, quoted CSV, or an escaped vendor grammar may
            # legitimately differ from the in-memory decoded value.
            try:
                parsed = json.loads(lexeme)
            except (ValueError, TypeError):
                parsed = object()
            if (
                ("JSON" in candidate.syntax.upper())
                and type(parsed) is type(occurrence.value)
                and parsed == occurrence.value
            ):
                decoded += 1
            else:
                unresolved += 1

    for i, left in enumerate(candidate.occurrences):
        for right in candidate.occurrences[i + 1:]:
            if _overlap(left, right) and not _valid_nested_overlap(left, right):
                errors.append("INCOMPATIBLE_FIELD_SPAN_OVERLAP")
                break
        if "INCOMPATIBLE_FIELD_SPAN_OVERLAP" in errors:
            break

    errors = list(dict.fromkeys(errors))
    return SpanAudit(not errors, tuple(errors), exact, decoded, unresolved)


def score_candidate(
    raw: str, candidate: CandidateResult, baseline: CandidateResult
) -> ShadowScore:
    """Minimal-description-length *proxy*, not calibrated probabilities.

    Residual bytes cost eight bits each. Every field boundary and name incurs
    a structural description cost, preventing 'more fields' from being free.
    The penalties are hypotheses that must be calibrated on training families.
    """
    audit = audit_candidate(raw, candidate, baseline)
    base_audit = audit_candidate(raw, baseline)
    current = Counter(map(_claim_key, candidate.occurrences))
    original = Counter(map(_claim_key, baseline.occurrences))
    extra = sum((current - original).values())
    # Unknown decoding in an existing baseline is preserved, but an inferred
    # *additional* field with an unverified decoder cannot be auto-promoted.
    unverified_new = max(0, audit.decoding_unverified - base_audit.decoding_unverified)
    errors = audit.errors + (
        ("INFERRED_FIELD_DECODING_UNVERIFIED",) if extra and unverified_new else ()
    )
    if errors:
        return ShadowScore(False, None, errors, extra, audit.decoding_unverified)

    length = max(1, candidate.source_bytes)
    residual = sum(region.end_byte - region.start_byte for region in candidate.residual_regions)
    location_bits = 2 * log2(length + 1)
    grammar_bits = sum(
        location_bits + 2 * log2(len(occ.display_path.encode("utf8")) + 1) + 4
        for occ in candidate.occurrences
    )
    unverified_bits = 8 * audit.decoding_unverified
    inferred_bits = 12 * sum(
        1 for occ in candidate.occurrences
        if occ.display_path.startswith(("funnel_residual.", "funnel_learned_partial."))
    )
    issue_bits = 12 * len(candidate.issues)
    total = 8 * residual + grammar_bits + unverified_bits + inferred_bits + issue_bits
    return ShadowScore(True, round(total, 6), (), extra, audit.decoding_unverified)


def choose_shadow(
    raw: str, candidates: Iterable[CandidateResult], baseline: CandidateResult,
) -> ShadowDecision:
    """Rerank a *fixed* supplied pool; never change the live product result."""
    pool = tuple(candidates)
    scores = tuple(score_candidate(raw, candidate, baseline) for candidate in pool)
    valid = [
        index for index, item in enumerate(scores)
        if item.valid and item.description_bits is not None
    ]
    if not valid:
        return ShadowDecision(None, scores, False)
    selected = min(
        valid,
        key=lambda index: (
            scores[index].description_bits,
            scores[index].new_claims,
            index,
        ),
    )
    same = Counter(map(_claim_key, pool[selected].occurrences)) == Counter(
        map(_claim_key, baseline.occurrences)
    )
    return ShadowDecision(selected, scores, same)
