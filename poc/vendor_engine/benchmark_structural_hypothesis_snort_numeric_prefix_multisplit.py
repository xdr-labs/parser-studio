"""Independent validation for cross-event numeric-prefix partial recovery.

The learner sees only raw training samples. Evaluation uses Elastic's pinned
Snort fast fixture, official SNORT_DATE grammar, and expected @timestamp output.
No expected values or product/vendor identity are inputs to the learner.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import LOCAL_CACHE, _events
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_partial_with_numeric_prefix,
    learn_leading_numeric_hypotheses,
    parse_leading_numeric_slots,
)

RAW = LOCAL_CACHE / "snort_fast.log"
EXPECTED = LOCAL_CACHE / "snort_fast_expected.json"
OUT = (
    Path(__file__).resolve().parent
    / "structural-hypothesis-snort-numeric-prefix-multisplit-summary.json"
)

SNORT_DATE = re.compile(
    r"^(?P<month>\d{1,2})/(?P<day>\d{1,2})"
    r"(?:/(?P<year>\d{2,4}))?-"
    r"(?P<hour>\d{1,2}):(?P<minute>\d{2}):"
    r"(?P<second>\d{2}(?:\.\d+)?)"
)


def _expected_by_original() -> dict[str, list[dict[str, Any]]]:
    payload = json.loads(EXPECTED.read_text("utf8"))
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in payload["expected"]:
        raw = doc.get("event", {}).get("original")
        if isinstance(raw, str):
            result[raw].append(doc)
    return result


def _official_components(raw: str) -> list[tuple[int, int, str]] | None:
    match = SNORT_DATE.match(raw)
    if match is None:
        return None
    names = ["month", "day"]
    if match.group("year") is not None:
        names.append("year")
    names.extend(["hour", "minute", "second"])
    return [
        (match.start(name), match.end(name), match.group(name))
        for name in names
    ]


def _timestamp_consistent(
    components: list[tuple[int, int, str]],
    docs: list[dict[str, Any]],
) -> bool:
    values = [value for _start, _end, value in components]
    # The current fast fixture has no source year. Expected output supplies it.
    if len(values) != 5:
        return False
    month, day, hour, minute, second = values
    sec_int, _, fraction = second.partition(".")
    for doc in docs:
        stamp = doc.get("@timestamp")
        if not isinstance(stamp, str):
            continue
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if (
            parsed.month == int(month)
            and parsed.day == int(day)
            and parsed.hour == int(hour)
            and parsed.minute == int(minute)
            and parsed.second == int(sec_int)
        ):
            if not fraction:
                return True
            expected_ms = f"{parsed.microsecond:06d}"[:3]
            if fraction[:3] == expected_ms:
                return True
    return False


def _evaluate(seed: str, rows: list[str], expected) -> dict[str, Any]:
    train, holdout = _split_seed(rows, seed)
    hypotheses = learn_leading_numeric_hypotheses(train)
    metrics = Counter()
    promoted_hashes: list[str] = []

    for raw in holdout:
        baseline = parse_security_multipass(raw)
        metrics["events"] += 1
        if baseline.status == "SOURCE_PARSED":
            metrics["baseline_complete"] += 1
            continue
        metrics["baseline_incomplete"] += 1

        candidate = parse_leading_numeric_slots(raw, hypotheses)
        augmented = augment_partial_with_numeric_prefix(baseline, candidate)
        if augmented is None or candidate is None:
            continue

        metrics["augmented_events"] += 1
        if augmented.status == "SOURCE_PARSED":
            metrics["unexpected_complete"] += 1
        if augmented.raw != baseline.raw:
            metrics["raw_mismatch"] += 1

        before = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        after = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in augmented.value_spans
        }
        if before <= after:
            metrics["baseline_span_preserved_events"] += 1
        else:
            metrics["baseline_span_loss_events"] += 1

        baseline_ranges = {
            (span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        additions = [
            span
            for span in augmented.value_spans
            if (span.start_byte, span.end_byte) not in baseline_ranges
        ]
        metrics["added_spans"] += len(additions)
        promoted_hashes.append(hashlib.sha256(raw.encode("utf8")).hexdigest())

        official = _official_components(raw)
        docs = expected.get(raw, [])
        if official is None:
            metrics["events_without_official_date"] += 1
            continue
        if docs:
            metrics["events_with_expected_doc"] += 1
        official_ranges = {
            (
                len(raw[:start].encode("utf8")),
                len(raw[:end].encode("utf8")),
            ): value
            for start, end, value in official
        }
        raw_bytes = raw.encode("utf8")
        for span in additions:
            key = (span.start_byte, span.end_byte)
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if key in official_ranges and value == official_ranges[key]:
                metrics["official_exact_span_value"] += 1
            else:
                metrics["unvalidated_spans"] += 1
        if _timestamp_consistent(official, docs):
            metrics["expected_timestamp_consistent_events"] += 1
        elif docs:
            metrics["expected_timestamp_inconsistent_events"] += 1

        # Safety: malformed shape/NUL must never become complete; this partial
        # layer also must not operate past the baseline NUL safety boundary.
        mutations = (
            raw.replace("/", "", 1),
            "X" + raw,
            raw[: max(1, len(raw) // 2)] + "\x00" + raw[len(raw) // 2 :],
        )
        for mutated in mutations:
            metrics["mutation_attempts"] += 1
            mutated_baseline = parse_security_multipass(mutated)
            mutated_candidate = parse_leading_numeric_slots(mutated, hypotheses)
            mutated_augmented = augment_partial_with_numeric_prefix(
                mutated_baseline, mutated_candidate
            )
            if mutated_augmented is not None:
                metrics["mutation_augmentation"] += 1
                if mutated_augmented.status == "SOURCE_PARSED":
                    metrics["mutation_false_complete"] += 1

    metrics["independently_validated_spans"] = metrics[
        "official_exact_span_value"
    ]
    return {
        "seed": seed,
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_count": len(hypotheses),
        "metrics": dict(metrics),
        "augmented_event_sha256": sorted(promoted_hashes),
    }


def run() -> dict[str, Any]:
    rows = _events(RAW)
    expected = _expected_by_original()
    splits = [_evaluate(seed, rows, expected) for seed in SEEDS]
    aggregate = Counter()
    unique_augmented = set()
    for split in splits:
        aggregate.update(split["metrics"])
        unique_augmented.update(split["augmented_event_sha256"])

    result = {
        "contract": (
            "parser-studio.poc.numeric-prefix-snort-reference-multisplit.v1"
        ),
        "scope": "SNORT_IDS_IPS_PARTIAL_SOURCE_VALUE_RECOVERY",
        "learner_vendor_identity_used": False,
        "learner_reference_values_used": False,
        "semantic_mapping_scored": False,
        "raw_values_published": False,
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "elastic_integrations_revision": (
            "57ac255efb40d98151337b4ff11b9015679391ed"
        ),
        "elastic_expected_blob_sha": (
            "d0daa4817ee0d8b01ba2bd68c7ab67ab8e71a7d3"
        ),
        "elastic_plaintext_pipeline_blob_sha": (
            "197aa96409995a42bba8f4c86ad1b01557724198"
        ),
        "official_grammar": (
            "SNORT_DATE=%{MONTHNUM}/%{MONTHDAY}(/%{YEAR})?-%{TIME}"
        ),
        "splits": splits,
        "aggregate_metrics": dict(aggregate),
        "unique_augmented_events": len(unique_augmented),
        "mutation_safety": {
            "attempts": aggregate["mutation_attempts"],
            "unexpected_augmentation": aggregate["mutation_augmentation"],
            "false_complete": aggregate["mutation_false_complete"],
        },
        "all_mutations_fail_closed": (
            aggregate["mutation_attempts"] > 0
            and aggregate["mutation_augmentation"] == 0
            and aggregate["mutation_false_complete"] == 0
        ),
        "all_added_spans_independently_validated": (
            aggregate["added_spans"] > 0
            and aggregate["added_spans"]
            == aggregate["independently_validated_spans"]
            and aggregate["unvalidated_spans"] == 0
        ),
        "status_policy": (
            "PARTIAL remains PARTIAL; numeric-prefix recovery cannot certify "
            "whole-record completeness"
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
