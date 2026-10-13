"""Exact raw-source-field scoring, independent of normalized Dictionary roles.

A true positive requires both the original source path and original typed
value to agree with an independently labeled expected source field. Counts
are occurrence-aware (repeated vendor fields are not silently deduplicated).
This module never inspects, guesses, or emits meaning/Dictionary mappings.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
import json
import re
from typing import Any

HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
STATES = {"SOURCE_PARSED", "PARTIAL", "RAW_ONLY", "STRUCTURED_EMPTY"}


@dataclass(frozen=True)
class SourceField:
    path: str
    value: Any


@dataclass(frozen=True)
class SourceRecord:
    raw_sha256: str
    fields: tuple[SourceField, ...]
    status: str
    raw_bytes: int
    unparsed_bytes: int


def _cell(field: SourceField) -> tuple[str, str]:
    if not isinstance(field.path, str) or not field.path or len(field.path)>256:
        raise ValueError("INVALID_SOURCE_FIELD_PATH")
    # Strict JSON spelling retains string-vs-number-vs-null and nested arrays.
    try:
        encoded = json.dumps(field.value,sort_keys=True,ensure_ascii=True,
                             separators=(",", ":"), allow_nan=False)
    except (ValueError,TypeError) as exc:
        raise ValueError("INVALID_SOURCE_FIELD_VALUE") from exc
    return field.path, encoded


def _validate(record: SourceRecord) -> None:
    if (not HEX_SHA256.fullmatch(record.raw_sha256)
        or record.status not in STATES or record.raw_bytes<0
        or record.unparsed_bytes<0 or record.unparsed_bytes>record.raw_bytes):
        raise ValueError("INVALID_SOURCE_RECORD_CONTRACT")
    if len(record.fields)>1024:
        raise ValueError("SOURCE_FIELD_COUNT_LIMIT")
    for f in record.fields:
        _cell(f)


def _metrics(tp: int, fp: int, fn: int) -> dict[str,Any]:
    denominator=2*tp+fp+fn
    return {"TP":tp,"FP":fp,"FN":fn,
            "precision":round(tp/(tp+fp),4) if tp+fp else None,
            "recall":round(tp/(tp+fn),4) if tp+fn else None,
            "f1":round(2*tp/denominator,4) if denominator else None}


def score_source_fields(reference:list[SourceRecord], observed:list[SourceRecord]) -> dict[str, Any]:
    """Same ordered original events. Values stay local; only counts returned."""
    if len(reference)!=len(observed):
        raise ValueError("SOURCE_EVENT_COUNT_MISMATCH")
    if len(reference)>100000:
        raise ValueError("SOURCE_EVENT_COUNT_LIMIT")
    tp=fp=fn=0
    statuses=Counter()
    total_bytes=total_residual=0
    ref_fields=obs_fields=0
    for r,o in zip(reference,observed):
        _validate(r);_validate(o)
        if r.raw_sha256!=o.raw_sha256 or r.raw_bytes!=o.raw_bytes:
            raise ValueError("SOURCE_RECORD_IDENTITY_MISMATCH")
        if r.status=="RAW_ONLY" and r.fields:
            raise ValueError("REFERENCE_RAW_ONLY_WITH_FIELDS")
        expected=Counter(_cell(f) for f in r.fields)
        actual=Counter(_cell(f) for f in o.fields)
        shared=expected&actual
        tp+=sum(shared.values())
        fp+=sum((actual-shared).values())
        fn+=sum((expected-shared).values())
        ref_fields+=sum(expected.values());obs_fields+=sum(actual.values())
        statuses[o.status]+=1
        total_bytes+=o.raw_bytes;total_residual+=o.unparsed_bytes
    return {
        "contract":"parser-studio.poc.source-field-metrics.v1",
        "scope":"RAW_VENDOR_SOURCE_FIELDS_ONLY_NO_DICTIONARY",
        "raw_records_accounted":len(reference),
        "gold_source_field_occurrences":ref_fields,
        "observed_source_field_occurrences":obs_fields,
        "exact_source_field":_metrics(tp,fp,fn),
        "fully_parsed_records":statuses["SOURCE_PARSED"],
        "partial_records":statuses["PARTIAL"],
        "raw_only_records":statuses["RAW_ONLY"],
        "structured_empty_records":statuses["STRUCTURED_EMPTY"],
        "source_bytes":total_bytes,
        "unparsed_bytes":total_residual,
        "source_coverage_rate":round((total_bytes-total_residual)/total_bytes,4) if total_bytes else None,
        "semantic_mapping_attempted":False,
        "stellar_native_verified":False,
        "warning":"Gold source-field labels must be independently produced; template match and raw byte retention do not create them.",
    }
