"""Independent three-split validation for aligned residual atoms on Snort IDS/IPS.

The learner receives only raw/source structural evidence and current baseline
parse results.  Elastic expected output and pipeline grammar are evaluation-only.
No raw values are serialized to tracked evidence.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import _events
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    augment_with_aligned_residual_atoms,
    delete_required_aligned_anchor,
    learn_aligned_residual_hypotheses,
)

BASE = Path(__file__).resolve().parent
CACHE = BASE / ".cache" / "structural_hypothesis_security"
FAST = CACHE / "snort_fast.log"
EXPECTED = CACHE / "snort_fast_expected.json"
OUT = BASE / "structural-hypothesis-snort-aligned-summary.json"

SNORT_DATE = re.compile(
    r"^(?P<month>\d{1,2})/(?P<day>\d{1,2})"
    r"(?:/(?P<year>\d{2,4}))?-"
    r"(?P<hour>\d{1,2}):(?P<minute>\d{2}):"
    r"(?P<second>\d{2})(?:\.(?P<fraction>\d+))?"
)


def _expected_by_original() -> dict[str, dict[str, Any]]:
    payload = json.loads(EXPECTED.read_text("utf8"))
    return {
        doc["event"]["original"]: doc
        for doc in payload["expected"]
        if isinstance(doc.get("event", {}).get("original"), str)
    }


def _timestamp_matches(raw_value: str, expected: dict[str, Any] | None) -> bool:
    if expected is None:
        return False
    match = SNORT_DATE.fullmatch(raw_value)
    stamp = expected.get("@timestamp")
    if match is None or not isinstance(stamp, str):
        return False
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return False
    if (
        parsed.month != int(match.group("month"))
        or parsed.day != int(match.group("day"))
        or parsed.hour != int(match.group("hour"))
        or parsed.minute != int(match.group("minute"))
        or parsed.second != int(match.group("second"))
    ):
        return False
    fraction = match.group("fraction")
    if fraction:
        expected_fraction = f"{parsed.microsecond:06d}"
        if fraction[:3] != expected_fraction[:3]:
            return False
    return True


def _span_identity(event) -> set[tuple[str, tuple | None, int, int]]:
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def _evaluate(seed: str, rows: list[str], expected_by_raw) -> dict[str, Any]:
    train, holdout = _split_seed(rows, seed)
    training = [parse_security_multipass(raw) for raw in train]
    hypotheses = learn_aligned_residual_hypotheses(training)
    metrics = Counter()
    promoted_hashes: list[str] = []

    for raw in holdout:
        baseline = parse_security_multipass(raw)
        assert_source_accounting(baseline)
        before = _span_identity(baseline)
        augmented = augment_with_aligned_residual_atoms(
            baseline, hypotheses
        )
        assert_source_accounting(augmented)
        after = _span_identity(augmented)

        metrics["events"] += 1
        metrics["baseline_partial"] += int(baseline.status == "PARTIAL")
        metrics["status_unchanged"] += int(augmented.status == baseline.status)
        if not before <= after:
            metrics["baseline_span_loss_events"] += 1
        added = [
            span for span in augmented.value_spans
            if (
                span.path,
                span.source_segments,
                span.start_byte,
                span.end_byte,
            ) not in before
        ]
        if not added:
            continue

        metrics["augmented_events"] += 1
        metrics["added_spans"] += len(added)
        promoted_hashes.append(hashlib.sha256(raw.encode("utf8")).hexdigest())
        raw_bytes = raw.encode("utf8")
        expected = expected_by_raw.get(raw)
        if expected is not None:
            metrics["augmented_events_with_official_expected"] += 1
        for span in added:
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if _timestamp_matches(value, expected):
                metrics["official_timestamp_exact"] += 1
            else:
                metrics["unvalidated_added_spans"] += 1

        # Counterexample qualification: deleting one learned literal anchor
        # must stop this layer from adding any source atom.
        mutated = delete_required_aligned_anchor(raw, baseline, hypotheses)
        if mutated is not None:
            metrics["anchor_deletion_attempts"] += 1
            mutated_baseline = parse_security_multipass(mutated)
            mutated_augmented = augment_with_aligned_residual_atoms(
                mutated_baseline, hypotheses
            )
            if len(mutated_augmented.value_spans) > len(mutated_baseline.value_spans):
                metrics["anchor_deletion_false_additions"] += 1

    return {
        "seed": seed,
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_count": len(hypotheses),
        "metrics": dict(metrics),
        "augmented_event_sha256": sorted(promoted_hashes),
    }


def run() -> dict[str, Any]:
    rows = _events(FAST)
    expected_by_raw = _expected_by_original()
    splits = [_evaluate(seed, rows, expected_by_raw) for seed in SEEDS]

    aggregate = Counter()
    unique = set()
    for split in splits:
        aggregate.update(split["metrics"])
        unique.update(split["augmented_event_sha256"])

    result = {
        "contract": "parser-studio.poc.snort-aligned-residual-atoms.v1",
        "scope": "SNORT_IDS_IPS_FAST_LOG_SOURCE_EXTRACTION",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "learner_vendor_identity_used": False,
        "learner_expected_reference_used": False,
        "raw_values_published": False,
        "upstream_repository": "elastic/integrations",
        "upstream_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "raw_fixture_blob_sha": "23a7b6e9b8c4853217e743a4813a6db32815c3f9",
        "expected_fixture_blob_sha": "d0daa4817ee0d8b01ba2bd68c7ab67ab8e71a7d3",
        "reference_pipeline_blob_sha": "197aa96409995a42bba8f4c86ad1b01557724198",
        "reference_source_pattern": "SNORT_DATE=%{MONTHNUM}/%{MONTHDAY}(/%{YEAR})?-%{TIME}",
        "split_count": len(splits),
        "splits": splits,
        "aggregate_metrics": dict(aggregate),
        "unique_augmented_events": len(unique),
        "acceptance": {
            "all_added_spans_independently_validated": (
                aggregate["added_spans"] > 0
                and aggregate["added_spans"]
                == aggregate["official_timestamp_exact"]
                and aggregate["unvalidated_added_spans"] == 0
            ),
            "baseline_span_loss_zero": aggregate["baseline_span_loss_events"] == 0,
            "status_never_promoted": (
                aggregate["status_unchanged"] == aggregate["events"]
            ),
            "anchor_deletion_false_additions_zero": (
                aggregate["anchor_deletion_false_additions"] == 0
            ),
        },
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
