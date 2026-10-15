"""Independent reference validation for NETSCOUT Sightline CSV-cell refinement.

The learner sees only raw training samples and existing Parser Studio source
events.  This evaluation-only oracle uses the explicit public Change Log
surface grammar from the pinned elastic/integrations fixture.  No oracle values
or vendor identity are available to the learner.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import _events
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    learn_csv_cell_label_hypotheses,
    refine_csv_cell_labels,
)

BASE = Path(__file__).resolve().parent
SOURCE = BASE / ".cache/structural_hypothesis_fresh_holdout/netscout_sightline/test-generated.log"
OUT = BASE / "structural-hypothesis-netscout-csv-label-multisplit-summary.json"

REFERENCE = re.compile(
    r"^.*?: Change Log: "
    r"Username:(?P<Username>[^,]+),\s*"
    r"Subsystem:(?P<Subsystem>[^,]+),\s*"
    r"Setting Type:(?P<Setting_Type>[^,]+),\s*"
    r"Message:(?P<Message>.*)$"
)
REFERENCE_LABELS = {
    "Username": "Username",
    "Subsystem": "Subsystem",
    "Setting Type": "Setting_Type",
    "Message": "Message",
}


def _reference_spans(raw: str) -> dict[str, tuple[int, int, str]] | None:
    match = REFERENCE.match(raw)
    if match is None:
        return None
    out: dict[str, tuple[int, int, str]] = {}
    for label, group in REFERENCE_LABELS.items():
        start, end = match.span(group)
        value = match.group(group)
        out[label] = (
            len(raw[:start].encode("utf8")),
            len(raw[:end].encode("utf8")),
            value,
        )
    return out


def _evaluate(seed: str, rows: list[str]) -> dict:
    train, holdout = _split_seed(rows, seed)
    training_events = [parse_security_multipass(raw) for raw in train]
    hypotheses = learn_csv_cell_label_hypotheses(training_events)
    metrics = Counter()
    augmented_sha: list[str] = []

    for raw in holdout:
        metrics["events"] += 1
        baseline = parse_security_multipass(raw)
        refined = refine_csv_cell_labels(baseline, hypotheses)
        reference = _reference_spans(raw)
        if reference is not None:
            metrics["reference_change_log_events"] += 1
        if refined is None:
            continue

        metrics["augmented_events"] += 1
        augmented_sha.append(hashlib.sha256(raw.encode("utf8")).hexdigest())
        if refined.status == "PARTIAL":
            metrics["still_partial"] += 1
        if refined.value_spans[: len(baseline.value_spans)] == baseline.value_spans:
            metrics["baseline_parent_spans_preserved"] += 1

        parent_count = len(baseline.value_spans)
        additions = refined.value_spans[parent_count:]
        metrics["added_spans"] += len(additions)
        if reference is None:
            metrics["augmented_without_reference"] += 1
            metrics["unvalidated_spans"] += len(additions)
            continue

        raw_bytes = raw.encode("utf8")
        for span in additions:
            segments = span.source_segments
            label = (
                segments[1]
                if segments is not None
                and len(segments) >= 2
                and segments[0] == "csv_refined"
                else None
            )
            expected = reference.get(str(label)) if label is not None else None
            actual = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if (
                expected is not None
                and (span.start_byte, span.end_byte) == expected[:2]
                and actual == expected[2]
            ):
                metrics["reference_exact_span_value"] += 1
            else:
                metrics["unvalidated_spans"] += 1

    metrics["independently_validated_spans"] = metrics[
        "reference_exact_span_value"
    ]
    return {
        "seed": seed,
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_widths": sorted(hypotheses),
        "metrics": dict(metrics),
        "augmented_event_sha256": sorted(augmented_sha),
    }


def run() -> dict:
    rows = _events(SOURCE)
    splits = [_evaluate(seed, rows) for seed in SEEDS]
    aggregate = Counter()
    unique_augmented: set[str] = set()
    for split in splits:
        aggregate.update(split["metrics"])
        unique_augmented.update(split["augmented_event_sha256"])

    result = {
        "contract": "parser-studio.poc.netscout-csv-cell-label-multisplit.v1",
        "scope": "NETSCOUT_SIGHTLINE_NDR_PARTIAL_CHILD_FIELD_RECOVERY",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "elastic_integrations_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "source_blob_sha": "bd8d089c540fb5140ca7fcafd91229222558985b",
        "learner_vendor_identity_used": False,
        "learner_reference_values_used": False,
        "semantic_mapping_scored": False,
        "raw_values_published": False,
        "reference_grammar": (
            "Change Log: Username:<value>, Subsystem:<value>, "
            "Setting Type:<value>, Message:<value>"
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
            "Parent CSV columns remain unchanged; child recovery cannot clear "
            "UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION or certify completeness."
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
