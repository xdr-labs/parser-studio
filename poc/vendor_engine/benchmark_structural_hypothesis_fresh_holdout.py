"""Prospective evaluation on the pre-frozen fresh security-product holdout.

The source set was committed before Parser Studio read or evaluated the fixtures.
This benchmark does not tune grammar thresholds.  It measures whether the frozen
v4 batch-learning primitives generalize to four previously unused product
families.  Raw values are never serialized.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    augment_partial_with_numeric_prefix,
    learn_best_hypothesis,
    learn_event_template_hypotheses,
    learn_leading_numeric_hypotheses,
    learn_relative_rgram_hypotheses,
    merge_residual_hypothesis,
    parse_leading_numeric_slots,
    parse_with_event_template,
    parse_with_hypothesis,
    parse_with_relative_rgram,
)

BASE = Path(__file__).resolve().parent
MANIFEST = BASE / "STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_20261015.json"
CACHE = BASE / ".cache" / "structural_hypothesis_fresh_holdout"
OUT = BASE / "structural-hypothesis-fresh-security-holdout-summary.json"


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _events(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text("utf8").splitlines()
        if line.strip()
    ]


def _strict_split(rows: list[str], seed: str) -> tuple[list[str], list[str]]:
    """Never reuse a short file as both train and holdout."""
    if len(rows) < 4:
        return [], list(rows)
    return _split_seed(rows, seed)


def _learn(train: list[str]) -> tuple[Any, dict, dict, dict]:
    if len(train) < 3:
        return None, {}, {}, {}
    training_events = [parse_security_multipass(raw) for raw in train]
    return (
        learn_best_hypothesis(train),
        learn_event_template_hypotheses(train),
        learn_relative_rgram_hypotheses(training_events),
        learn_leading_numeric_hypotheses(train),
    )


def _evaluate_event(
    raw: str,
    delimited,
    templates: dict,
    rgrams: dict,
    numeric: dict,
) -> Counter:
    metrics = Counter()
    baseline = parse_security_multipass(raw)
    assert_source_accounting(baseline)
    metrics["events"] += 1
    metrics[f"baseline_{baseline.status}"] += 1
    if baseline.status == "SOURCE_PARSED":
        return metrics

    merged = None
    chosen = None
    if delimited is not None:
        candidate = parse_with_hypothesis(raw, delimited)
        merged = merge_residual_hypothesis(baseline, candidate)
        if merged is not None:
            chosen = "delimited"

    if merged is None and templates:
        candidate = parse_with_event_template(raw, templates)
        merged = merge_residual_hypothesis(baseline, candidate)
        if merged is not None:
            chosen = "template"

    if merged is None and rgrams:
        candidate = parse_with_relative_rgram(raw, baseline, rgrams)
        merged = merge_residual_hypothesis(baseline, candidate)
        if merged is not None:
            chosen = "rgram"

    if merged is not None:
        assert_source_accounting(merged)
        metrics["complete_promotions"] += 1
        metrics[f"{chosen}_promotions"] += 1
        metrics["complete_source_span_gain"] += (
            len(merged.value_spans) - len(baseline.value_spans)
        )
        metrics["complete_residual_byte_reduction"] += (
            baseline.residual_bytes - merged.residual_bytes
        )
        baseline_set = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        merged_set = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in merged.value_spans
        }
        if baseline_set <= merged_set:
            metrics["complete_baseline_span_preserved"] += 1
        else:
            metrics["complete_baseline_span_loss"] += 1
        if merged.raw != baseline.raw:
            metrics["complete_raw_mismatch"] += 1

    if numeric:
        numeric_candidate = parse_leading_numeric_slots(raw, numeric)
        partial = augment_partial_with_numeric_prefix(
            baseline, numeric_candidate
        )
        if partial is not None:
            assert_source_accounting(partial)
            metrics["partial_augmented_events"] += 1
            metrics["partial_source_span_gain"] += (
                len(partial.value_spans) - len(baseline.value_spans)
            )
            if partial.status == "SOURCE_PARSED":
                metrics["partial_unexpected_complete"] += 1
            baseline_set = {
                (span.path, span.source_segments, span.start_byte, span.end_byte)
                for span in baseline.value_spans
            }
            partial_set = {
                (span.path, span.source_segments, span.start_byte, span.end_byte)
                for span in partial.value_spans
            }
            if baseline_set <= partial_set:
                metrics["partial_baseline_span_preserved"] += 1
            else:
                metrics["partial_baseline_span_loss"] += 1
            if partial.raw != baseline.raw:
                metrics["partial_raw_mismatch"] += 1

    return metrics


def run_seed(
    seed: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    totals = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    per_file: list[dict[str, Any]] = []

    for source in manifest["files"]:
        family = source["family"]
        path = CACHE / family / Path(source["path"]).name
        data = path.read_bytes()
        actual_blob = _git_blob_sha(data)
        if actual_blob != source["blob_sha"]:
            raise RuntimeError(
                "FRESH_HOLDOUT_BLOB_MISMATCH:"
                + source["path"]
            )

        rows = _events(path)
        train, holdout = _strict_split(rows, seed)
        delimited, templates, rgrams, numeric = _learn(train)
        metrics = Counter()
        for raw in holdout:
            metrics.update(
                _evaluate_event(
                    raw, delimited, templates, rgrams, numeric
                )
            )
        totals.update(metrics)
        by_family[family].update(metrics)
        per_file.append(
            {
                "family": family,
                "category": source["category"],
                "path": source["path"],
                "blob_sha": source["blob_sha"],
                "event_count": len(rows),
                "train_count": len(train),
                "holdout_count": len(holdout),
                "hypotheses": {
                    "delimited": int(delimited is not None),
                    "template": len(templates),
                    "relative_rgram": len(rgrams),
                    "numeric_prefix": len(numeric),
                },
                "metrics": dict(metrics),
            }
        )

    return {
        "seed": seed,
        "totals": dict(totals),
        "by_family": {
            key: dict(value)
            for key, value in sorted(by_family.items())
        },
        "per_file": per_file,
    }


def run() -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text("utf8"))
    if manifest.get("frozen_before_evaluation") is not True:
        raise RuntimeError("FRESH_HOLDOUT_NOT_PREFROZEN")

    splits = [run_seed(seed, manifest) for seed in SEEDS]
    aggregate = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    for split in splits:
        aggregate.update(split["totals"])
        for family, metrics in split["by_family"].items():
            by_family[family].update(metrics)

    result = {
        "contract": (
            "parser-studio.poc.structural-hypothesis-fresh-security-"
            "prospective.v1"
        ),
        "scope": "SECURITY_PRODUCTS_ONLY_FRESH_HOLDOUT",
        "manifest_contract": manifest["contract"],
        "manifest_file_set_sha256": manifest["file_set_sha256"],
        "upstream_repository": manifest["upstream_repository"],
        "upstream_revision": manifest["upstream_revision"],
        "source_engine_head": (
            "4596f4629a4cb7b900eb459cadffb0d2813c7957"
        ),
        "hypothesis_engine_revision": "v4-frozen-before-fresh-evaluation",
        "product_vendor_identity_used_by_learner": False,
        "raw_values_published": False,
        "short_file_train_holdout_reuse": False,
        "split_count": len(splits),
        "families": manifest["families"],
        "splits": splits,
        "aggregate_totals": dict(aggregate),
        "aggregate_by_family": {
            key: dict(value)
            for key, value in sorted(by_family.items())
        },
        "prospective_gain": {
            "complete_promotions": aggregate["complete_promotions"],
            "complete_source_span_gain": aggregate[
                "complete_source_span_gain"
            ],
            "partial_augmented_events": aggregate[
                "partial_augmented_events"
            ],
            "partial_source_span_gain": aggregate[
                "partial_source_span_gain"
            ],
        },
        "interpretation": (
            "A zero gain is an honest abstention result, not a failure of "
            "baseline parsing. Any tuning after this run turns these fixtures "
            "into development data and requires a new pre-frozen holdout."
        ),
    }
    OUT.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        "utf8",
    )
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
