"""Development-only multisplit validation for residual typed-label recovery.

The first fresh holdout became development data after its prospective zero-gain
result was recorded. The learner receives mixed security-product events only;
vendor identity and official expected values are evaluation-only.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_partial_with_residual_typed_labels,
    learn_residual_typed_label_hypotheses,
)

BASE = Path(__file__).resolve().parent
CACHE = BASE / ".cache" / "structural_hypothesis_fresh_holdout"
MANIFEST = BASE / "STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_20261015.json"
OUT = BASE / "structural-hypothesis-watchguard-typed-label-multisplit-summary.json"

EXPECTED = (
    ("watchguard_firebox", "test-alarm.log"),
    ("watchguard_firebox", "test-diagnostic.log"),
    ("watchguard_firebox", "test-event.log"),
    ("watchguard_firebox", "test-traffic.log"),
    ("barracuda_waf", "test-network-firewall.log"),
)


def _events(path: Path) -> list[str]:
    return [line for line in path.read_text("utf8").splitlines() if line.strip()]


def _all_rows() -> list[tuple[str, str, str]]:
    manifest = json.loads(MANIFEST.read_text("utf8"))
    rows: list[tuple[str, str, str]] = []
    for item in manifest["files"]:
        path = CACHE / item["family"] / Path(item["path"]).name
        for raw in _events(path):
            rows.append((item["family"], path.name, raw))
    return rows


def _expected_by_raw() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for family, name in EXPECTED:
        path = CACHE / family / (name + "-expected.json")
        if not path.exists():
            continue
        for doc in json.loads(path.read_text("utf8"))["expected"]:
            raw = doc.get("event", {}).get("original")
            if isinstance(raw, str):
                result[raw] = doc
    return result


def _leaves(obj: Any, path: tuple = ()) -> list[tuple[tuple, Any]]:
    if isinstance(obj, dict):
        out = []
        for key, value in obj.items():
            if path == () and key in {"message", "tags", "ecs"}:
                continue
            if path == ("event",) and key == "original":
                continue
            out.extend(_leaves(value, path + (key,)))
        return out
    if isinstance(obj, list):
        out = []
        for index, value in enumerate(obj):
            out.extend(_leaves(value, path + (index,)))
        return out
    return [(path, obj)]


def _split_rows(rows, seed):
    ordered = sorted(
        rows,
        key=lambda item: hashlib.sha256(
            (seed + "|" + item[2]).encode("utf8")
        ).hexdigest(),
    )
    count = max(3, min(len(ordered) - 1, round(len(ordered) * 0.65)))
    return ordered[:count], ordered[count:]


def _break_all_labels(raw: str, labels: set[str]) -> str:
    out = raw
    for label in sorted(labels, key=len, reverse=True):
        out = re.sub(
            re.escape(label) + r"\s*=",
            label + ":",
            out,
        )
    return out


def run_seed(seed: str, rows, expected) -> dict[str, Any]:
    train, holdout = _split_rows(rows, seed)
    training_events = [parse_security_multipass(raw) for _, _, raw in train]
    hypotheses = learn_residual_typed_label_hypotheses(training_events)
    metrics = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    learned_labels = set(hypotheses)

    for family, _name, raw in holdout:
        baseline = parse_security_multipass(raw)
        augmented = augment_partial_with_residual_typed_labels(
            baseline, hypotheses
        )
        if augmented is None:
            continue

        metrics["augmented_events"] += 1
        by_family[family]["augmented_events"] += 1
        if augmented.status != "SOURCE_PARSED":
            metrics["still_incomplete"] += 1
        else:
            metrics["unexpected_complete"] += 1

        base_spans = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        aug_spans = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in augmented.value_spans
        }
        if base_spans <= aug_spans:
            metrics["baseline_span_preserved"] += 1
        else:
            metrics["baseline_span_loss"] += 1

        doc = expected.get(raw)
        flat = _leaves(doc) if doc is not None else []
        if doc is not None:
            metrics["events_with_official_expected"] += 1
        raw_bytes = raw.encode("utf8")
        baseline_ranges = {
            (span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        for span in augmented.value_spans:
            key = (span.start_byte, span.end_byte)
            if key in baseline_ranges:
                continue
            metrics["added_spans"] += 1
            by_family[family]["added_spans"] += 1
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if any(str(expected_value) == value for _p, expected_value in flat):
                metrics["independent_exact_value"] += 1
                by_family[family]["independent_exact_value"] += 1
            else:
                metrics["unvalidated_spans"] += 1
                by_family[family]["unvalidated_spans"] += 1

        # NUL and broken label assignment must fail closed for this layer.
        mutations = [
            raw[: len(raw)//2] + "\x00" + raw[len(raw)//2 :],
            _break_all_labels(raw, learned_labels),
        ]
        for mutated in mutations:
            if mutated == raw:
                continue
            metrics["mutation_attempts"] += 1
            mutated_base = parse_security_multipass(mutated)
            mutated_aug = augment_partial_with_residual_typed_labels(
                mutated_base, hypotheses
            )
            if mutated_aug is not None:
                metrics["mutation_augmentation"] += 1
                if mutated_aug.status == "SOURCE_PARSED":
                    metrics["mutation_false_complete"] += 1

    return {
        "seed": seed,
        "train_events": len(train),
        "holdout_events": len(holdout),
        "learned_labels": sorted(learned_labels),
        "metrics": dict(metrics),
        "by_family": {k: dict(v) for k, v in sorted(by_family.items())},
    }


def run() -> dict[str, Any]:
    rows = _all_rows()
    expected = _expected_by_raw()
    splits = [run_seed(seed, rows, expected) for seed in SEEDS]
    aggregate = Counter()
    labels = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    for split in splits:
        aggregate.update(split["metrics"])
        labels.update(split["learned_labels"])
        for family, values in split["by_family"].items():
            by_family[family].update(values)

    result = {
        "contract": "parser-studio.poc.residual-typed-label-development.v1",
        "scope": "FIRST_FRESH_HOLDOUT_DEVELOPMENT_ONLY",
        "prospective_claim_allowed": False,
        "learner_vendor_identity_used": False,
        "learner_reference_values_used": False,
        "raw_values_published": False,
        "split_count": len(splits),
        "aggregate_metrics": dict(aggregate),
        "learned_label_occurrences_across_splits": dict(sorted(labels.items())),
        "aggregate_by_family": {
            k: dict(v) for k, v in sorted(by_family.items())
        },
        "all_added_spans_independently_validated": (
            aggregate["added_spans"] > 0
            and aggregate["added_spans"] == aggregate["independent_exact_value"]
            and aggregate["unvalidated_spans"] == 0
        ),
        "all_mutations_fail_closed": (
            aggregate["mutation_attempts"] > 0
            and aggregate["mutation_augmentation"] == 0
            and aggregate["mutation_false_complete"] == 0
        ),
        "splits": splits,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
