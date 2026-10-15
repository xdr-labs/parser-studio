"""Independent three-split validation for aligned residual atoms on WatchGuard Firebox.

The learner uses only raw/source structural evidence and current baseline parse
results. Elastic expected output and the WatchGuard ingest pipeline are
evaluation-only. Raw values are never serialized to tracked evidence.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import LOCAL_CACHE, _events
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    augment_with_aligned_residual_atoms,
    delete_required_aligned_anchor,
    learn_aligned_residual_hypotheses,
)

BASE = Path(__file__).resolve().parent
OUT = BASE / "structural-hypothesis-watchguard-aligned-summary.json"

SOURCES = (
    (
        "alarm",
        LOCAL_CACHE / "watchguard_alarm.log",
        LOCAL_CACHE / "watchguard_alarm_expected.json",
        "cbe4f31b2abf3165400f33b3bed612a3c0a1f9f9",
        "8bd8cb5643700efbda62b77b7a25408d0f644993",
    ),
    (
        "diagnostic",
        LOCAL_CACHE / "watchguard_diagnostic.log",
        LOCAL_CACHE / "watchguard_diagnostic_expected.json",
        "b07f9c2a36f04c602aebc7a6f27fef5fe09ed3e1",
        "82374d251243ada7201c790f870427763466d378",
    ),
    (
        "event",
        LOCAL_CACHE / "watchguard_event.log",
        LOCAL_CACHE / "watchguard_event_expected.json",
        "d0fa1cb7901a6722f74b6efca04eafb73d009137",
        "7fabe2679ff254eea00a5ec685dea2539ec5bcb6",
    ),
)

PIPELINE_BLOB_SHA = "4c64981d839ccbbf403490fc6ab646cfbebdf604"


def _expected(path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text("utf8"))
    return {
        doc["event"]["original"]: doc
        for doc in payload["expected"]
        if isinstance(doc.get("event", {}).get("original"), str)
    }


def _expected_timestamp(doc: dict[str, Any] | None) -> str | None:
    if doc is None:
        return None
    value = (
        doc.get("watchguard_firebox", {})
        .get("log", {})
        .get("timestamp")
    )
    return value if isinstance(value, str) else None


def _source_timestamp_matches(value: str, expected: str | None) -> bool:
    if expected is None:
        return False
    # The pinned WatchGuard pipeline parses a source ISO8601 value and
    # normalizes it to millisecond UTC. The raw fixture omits the trailing
    # normalized fraction/zone.
    return (
        expected == value
        or expected.startswith(value + ".")
        or expected.startswith(value + "Z")
    )


def _identity(event) -> set[tuple[str, tuple | None, int, int]]:
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def _evaluate_source(
    seed: str,
    rows: list[str],
    expected_by_raw: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    train, holdout = _split_seed(rows, seed)
    training = [parse_security_multipass(raw) for raw in train]
    hypotheses = learn_aligned_residual_hypotheses(training)
    metrics = Counter()

    for raw in holdout:
        baseline = parse_security_multipass(raw)
        assert_source_accounting(baseline)
        before = _identity(baseline)
        augmented = augment_with_aligned_residual_atoms(
            baseline, hypotheses
        )
        assert_source_accounting(augmented)
        after = _identity(augmented)

        metrics["events"] += 1
        metrics["baseline_complete"] += int(
            baseline.status == "SOURCE_PARSED"
        )
        metrics["baseline_incomplete"] += int(
            baseline.status != "SOURCE_PARSED"
        )
        metrics["status_unchanged"] += int(
            augmented.status == baseline.status
        )
        if not before <= after:
            metrics["baseline_span_loss_events"] += 1

        additions = [
            span for span in augmented.value_spans
            if (
                span.path,
                span.source_segments,
                span.start_byte,
                span.end_byte,
            ) not in before
        ]
        if not additions:
            continue

        metrics["augmented_events"] += 1
        metrics["added_spans"] += len(additions)
        raw_bytes = raw.encode("utf8")
        expected_value = _expected_timestamp(expected_by_raw.get(raw))
        if expected_value is not None:
            metrics["augmented_events_with_official_expected"] += 1

        for span in additions:
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if _source_timestamp_matches(value, expected_value):
                metrics["official_timestamp_exact"] += 1
            else:
                metrics["unvalidated_added_spans"] += 1

        mutated = delete_required_aligned_anchor(
            raw, baseline, hypotheses
        )
        if mutated is not None:
            metrics["anchor_deletion_attempts"] += 1
            mutated_baseline = parse_security_multipass(mutated)
            mutated_before = _identity(mutated_baseline)
            mutated_augmented = augment_with_aligned_residual_atoms(
                mutated_baseline, hypotheses
            )
            mutated_after = _identity(mutated_augmented)
            if mutated_after - mutated_before:
                metrics["anchor_deletion_false_additions"] += 1

    return {
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_count": len(hypotheses),
        "metrics": dict(metrics),
    }


def run() -> dict[str, Any]:
    splits = []
    aggregate = Counter()

    for seed in SEEDS:
        source_results = []
        split_metrics = Counter()
        for name, raw_path, expected_path, raw_blob, expected_blob in SOURCES:
            rows = _events(raw_path)
            expected_by_raw = _expected(expected_path)
            result = _evaluate_source(seed, rows, expected_by_raw)
            split_metrics.update(result["metrics"])
            source_results.append(
                {
                    "name": name,
                    "raw_blob_sha": raw_blob,
                    "expected_blob_sha": expected_blob,
                    **result,
                }
            )
        aggregate.update(split_metrics)
        splits.append(
            {
                "seed": seed,
                "metrics": dict(split_metrics),
                "sources": source_results,
            }
        )

    result = {
        "contract": "parser-studio.poc.watchguard-aligned-residual-atoms.v1",
        "scope": "WATCHGUARD_FIREBOX_SOURCE_EXTRACTION",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "learner_vendor_identity_used": False,
        "learner_expected_reference_used": False,
        "raw_values_published": False,
        "upstream_repository": "elastic/integrations",
        "upstream_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "reference_pipeline_blob_sha": PIPELINE_BLOB_SHA,
        "reference_field": "watchguard_firebox.log.timestamp",
        "split_count": len(splits),
        "splits": splits,
        "aggregate_metrics": dict(aggregate),
        "acceptance": {
            "all_added_spans_independently_validated": (
                aggregate["added_spans"] > 0
                and aggregate["added_spans"]
                == aggregate["official_timestamp_exact"]
                and aggregate["unvalidated_added_spans"] == 0
            ),
            "baseline_span_loss_zero": (
                aggregate["baseline_span_loss_events"] == 0
            ),
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
