"""Independent validation for Sophos UTM numeric-prefix partial recovery.

The learner receives only raw training rows. Evaluation uses Elastic's pinned
Sophos UTM pipeline timestamp grammar and expected @timestamp documents.
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
from benchmark_structural_hypothesis_security import LOCAL_CACHE, POSTFREEZE, _events
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_partial_with_numeric_prefix,
    learn_leading_numeric_hypotheses,
    parse_leading_numeric_slots,
)

SOURCES = (
    (
        POSTFREEZE / "sophos_utm" / "test-sophos-utm-dhcp.log",
        LOCAL_CACHE / "sophos_utm_dhcp_expected.json",
        "488d20eed82f895d7b57111abfc103138b892ad1",
    ),
    (
        POSTFREEZE / "sophos_utm" / "test-sophos-utm-dns.log",
        LOCAL_CACHE / "sophos_utm_dns_expected.json",
        "b23763fb138eeea969a02ee57b5715a7bc8a53c6",
    ),
)
PIPELINE_SHA = "99cd308d7d68bc1e194f949201f22537fbc4586d"
OUT = (
    Path(__file__).resolve().parent
    / "structural-hypothesis-sophos-numeric-prefix-multisplit-summary.json"
)

SOPHOS_TIMESTAMP = re.compile(
    r"^(?P<year>\d{4}):(?P<month>\d{1,2}):(?P<day>\d{1,2})-"
    r"(?P<hour>\d{1,2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)


def _expected_map(path: Path) -> dict[str, list[dict[str, Any]]]:
    payload = json.loads(path.read_text("utf8"))
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in payload["expected"]:
        raw = doc.get("event", {}).get("original")
        if isinstance(raw, str):
            result[raw].append(doc)
    return result


def _official_components(raw: str) -> list[tuple[int, int, str]] | None:
    match = SOPHOS_TIMESTAMP.match(raw)
    if match is None:
        return None
    names = ["year", "month", "day", "hour", "minute", "second"]
    return [
        (match.start(name), match.end(name), match.group(name))
        for name in names
    ]


def _timestamp_consistent(
    components: list[tuple[int, int, str]],
    docs: list[dict[str, Any]],
) -> bool:
    if len(components) != 6:
        return False
    year, month, day, hour, minute, second = [
        int(value) for _start, _end, value in components
    ]
    for doc in docs:
        stamp = doc.get("@timestamp")
        if not isinstance(stamp, str):
            continue
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if (
            parsed.year == year
            and parsed.month == month
            and parsed.day == day
            and parsed.hour == hour
            and parsed.minute == minute
            and parsed.second == second
        ):
            return True
    return False


def _evaluate_file(
    seed: str,
    raw_path: Path,
    expected_path: Path,
) -> dict[str, Any]:
    rows = _events(raw_path)
    train, holdout = _split_seed(rows, seed)
    hypotheses = learn_leading_numeric_hypotheses(train)
    expected = _expected_map(expected_path)
    metrics = Counter()
    augmented_hashes: list[str] = []

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
            (s.path, s.source_segments, s.start_byte, s.end_byte)
            for s in baseline.value_spans
        }
        after = {
            (s.path, s.source_segments, s.start_byte, s.end_byte)
            for s in augmented.value_spans
        }
        if before <= after:
            metrics["baseline_span_preserved_events"] += 1
        else:
            metrics["baseline_span_loss_events"] += 1

        baseline_ranges = {
            (s.start_byte, s.end_byte) for s in baseline.value_spans
        }
        additions = [
            s for s in augmented.value_spans
            if (s.start_byte, s.end_byte) not in baseline_ranges
        ]
        metrics["added_spans"] += len(additions)
        augmented_hashes.append(hashlib.sha256(raw.encode("utf8")).hexdigest())

        official = _official_components(raw)
        docs = expected.get(raw, [])
        if docs:
            metrics["events_with_expected_doc"] += 1
        if official is None:
            metrics["events_without_official_timestamp"] += 1
            continue

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

        mutations = (
            raw.replace(":", "", 1),
            "X" + raw,
            raw[: max(1, len(raw) // 2)] + "\x00" + raw[len(raw) // 2 :],
        )
        for mutated in mutations:
            metrics["mutation_attempts"] += 1
            mb = parse_security_multipass(mutated)
            mc = parse_leading_numeric_slots(mutated, hypotheses)
            ma = augment_partial_with_numeric_prefix(mb, mc)
            if ma is not None and ma.status == "SOURCE_PARSED":
                metrics["mutation_false_complete"] += 1

    metrics["independently_validated_spans"] = metrics[
        "official_exact_span_value"
    ]
    return {
        "source_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "expected_sha256": hashlib.sha256(expected_path.read_bytes()).hexdigest(),
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_count": len(hypotheses),
        "metrics": dict(metrics),
        "augmented_event_sha256": sorted(augmented_hashes),
    }


def run() -> dict[str, Any]:
    splits = []
    aggregate = Counter()
    unique_augmented = set()
    for seed in SEEDS:
        files = []
        seed_metrics = Counter()
        for raw_path, expected_path, expected_blob_sha in SOURCES:
            row = _evaluate_file(seed, raw_path, expected_path)
            row["file"] = raw_path.name
            row["elastic_expected_blob_sha"] = expected_blob_sha
            files.append(row)
            seed_metrics.update(row["metrics"])
            unique_augmented.update(row["augmented_event_sha256"])
        splits.append({
            "seed": seed,
            "metrics": dict(seed_metrics),
            "files": files,
        })
        aggregate.update(seed_metrics)

    result = {
        "contract": (
            "parser-studio.poc.numeric-prefix-sophos-utm-reference-"
            "multisplit.v1"
        ),
        "scope": "SOPHOS_UTM_PARTIAL_SOURCE_VALUE_RECOVERY",
        "learner_vendor_identity_used": False,
        "learner_reference_values_used": False,
        "semantic_mapping_scored": False,
        "raw_values_published": False,
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "elastic_integrations_revision": (
            "57ac255efb40d98151337b4ff11b9015679391ed"
        ),
        "elastic_pipeline_blob_sha": PIPELINE_SHA,
        "official_grammar": (
            "SOPHOS_TIMESTAMP=YEAR:MONTHNUM:MONTHDAY-HOUR:MINUTE:SECOND"
        ),
        "splits": splits,
        "aggregate_metrics": dict(aggregate),
        "unique_augmented_events": len(unique_augmented),
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
