"""Independent reference validation for Symantec Endpoint CSV-cell refinement."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import _events
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    learn_csv_cell_label_hypotheses,
    refine_csv_cell_labels,
)

BASE = Path(__file__).resolve().parent
ROOT = BASE / ".cache/structural_hypothesis_fresh_holdout/symantec_endpoint"
EXPECTED = ROOT / "test-system.log-expected.json"
OUT = BASE / "structural-hypothesis-symantec-csv-label-multisplit-summary.json"


def _rows() -> list[str]:
    rows: list[str] = []
    for path in sorted(ROOT.glob("*.log")):
        rows.extend(_events(path))
    return rows


def _expected_by_raw() -> dict[str, dict]:
    payload = json.loads(EXPECTED.read_text("utf8"))
    return {
        item["event"]["original"]: item
        for item in payload["expected"]
        if isinstance(item.get("event", {}).get("original"), str)
    }


def _reference_range(raw: str, label: str) -> tuple[int, int] | None:
    literal = label + ":"
    pos = raw.find(literal)
    if pos < 0:
        return None
    start = pos + len(literal)
    while start < len(raw) and raw[start].isspace():
        start += 1
    end = raw.find(",", start)
    if end < 0:
        end = len(raw)
    while end > start and raw[end - 1].isspace():
        end -= 1
    return (
        len(raw[:start].encode("utf8")),
        len(raw[:end].encode("utf8")),
    )


def _evaluate(seed: str, rows: list[str], expected: dict[str, dict]) -> dict:
    train, holdout = _split_seed(rows, seed)
    hypotheses = learn_csv_cell_label_hypotheses(
        [parse_security_multipass(raw) for raw in train]
    )
    metrics = Counter()
    augmented_sha: list[str] = []

    for raw in holdout:
        metrics["events"] += 1
        baseline = parse_security_multipass(raw)
        refined = refine_csv_cell_labels(baseline, hypotheses)
        if refined is None:
            continue
        metrics["augmented_events"] += 1
        augmented_sha.append(hashlib.sha256(raw.encode("utf8")).hexdigest())
        if refined.status == "PARTIAL":
            metrics["still_partial"] += 1
        if refined.value_spans[: len(baseline.value_spans)] == baseline.value_spans:
            metrics["baseline_parent_spans_preserved"] += 1

        doc = expected.get(raw)
        if doc is not None:
            metrics["events_with_expected_doc"] += 1
        native = (
            {
                "Site": doc["symantec_endpoint"]["log"]["site"],
                "Server": doc["symantec_endpoint"]["log"]["server"],
            }
            if doc is not None
            else {}
        )
        additions = refined.value_spans[len(baseline.value_spans):]
        metrics["added_spans"] += len(additions)
        raw_bytes = raw.encode("utf8")
        for span in additions:
            segments = span.source_segments
            label = (
                str(segments[1])
                if segments is not None
                and len(segments) >= 2
                and segments[0] == "csv_refined"
                else ""
            )
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            expected_range = _reference_range(raw, label)
            if (
                label in native
                and value == native[label]
                and expected_range == (span.start_byte, span.end_byte)
            ):
                metrics["official_exact_span_value"] += 1
            else:
                metrics["unvalidated_spans"] += 1

    metrics["independently_validated_spans"] = metrics[
        "official_exact_span_value"
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
    rows = _rows()
    expected = _expected_by_raw()
    splits = [_evaluate(seed, rows, expected) for seed in SEEDS]
    aggregate = Counter()
    unique_augmented: set[str] = set()
    for split in splits:
        aggregate.update(split["metrics"])
        unique_augmented.update(split["augmented_event_sha256"])

    result = {
        "contract": "parser-studio.poc.symantec-csv-cell-label-multisplit.v1",
        "scope": "SYMANTEC_ENDPOINT_PARTIAL_CHILD_FIELD_RECOVERY",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "elastic_integrations_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "elastic_expected_blob_sha": "a56bba80b6d64426e2c01777b016c7b4f56c3016",
        "learner_vendor_identity_used": False,
        "learner_reference_values_used": False,
        "semantic_mapping_scored": False,
        "raw_values_published": False,
        "reference_fields": ["Site", "Server"],
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
            "Parent CSV columns remain unchanged; child recovery remains PARTIAL."
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
