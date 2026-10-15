"""Repeatability check for the security-only Structural Hypothesis PoC.

Runs three deterministic train/holdout splits over the same pinned security
product sources.  Raw values are never serialized to the result.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from benchmark_structural_hypothesis_security import _events, _files
from multipass_adjudicator import parse_security_multipass, parse_security_once
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    augment_partial_with_numeric_prefix,
    delete_required_delimited_anchors,
    delete_required_rgram_literal,
    delete_required_template_anchor,
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
SUMMARY = BASE / "structural-hypothesis-security-multisplit-summary.json"
SEEDS = (
    "structural-hypothesis-security-ms-a",
    "structural-hypothesis-security-ms-b",
    "structural-hypothesis-security-ms-c",
)


def _split_seed(rows: list[str], seed: str) -> tuple[list[str], list[str]]:
    if len(rows) < 4:
        return rows, rows
    ordered = sorted(
        rows,
        key=lambda raw: hashlib.sha256(
            (seed + "|" + raw).encode("utf8")
        ).hexdigest(),
    )
    train_count = max(3, min(len(rows) - 1, round(len(rows) * 0.65)))
    return ordered[:train_count], ordered[train_count:]


def _mutations(
    raw: str,
    chosen: str,
    delimited,
    templates,
    rgrams,
    structural_view,
) -> list[str]:
    result = [
        raw[: max(1, int(len(raw) * 0.60))],
        raw[: max(1, int(len(raw) * 0.80))],
        raw[max(1, int(len(raw) * 0.20)) :],
        raw[: max(1, len(raw) // 2)] + "\x00" + raw[len(raw) // 2 :],
    ]
    structural = (
        delete_required_delimited_anchors(raw, delimited)
        if chosen == "delimited"
        else delete_required_template_anchor(raw, templates)
        if chosen == "template"
        else delete_required_rgram_literal(
            raw, structural_view, rgrams
        )
    )
    if structural is not None:
        result.append(structural)
    return result


def run_seed(seed: str) -> dict:
    totals = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    span_gain = 0
    residual_reduction = 0
    mutation_attempts = 0
    mutation_false_complete = 0
    promotion_span_preserved = 0
    promotion_span_loss = 0
    promotion_raw_mismatch = 0
    partial_augmented_events = 0
    partial_source_span_gain = 0
    partial_span_loss = 0
    partial_raw_mismatch = 0

    for source in _files():
        path = Path(source["path"])
        if not path.exists():
            continue
        rows = _events(path)
        if not rows:
            continue
        train, holdout = _split_seed(rows, seed)
        delimited = learn_best_hypothesis(train)
        templates = learn_event_template_hypotheses(train)
        rgrams = learn_relative_rgram_hypotheses(
            [parse_security_once(raw) for raw in train]
        )
        numeric = learn_leading_numeric_hypotheses(train)

        for raw in holdout:
            baseline = parse_security_multipass(raw)
            assert_source_accounting(baseline)
            totals["events"] += 1
            by_family[source["family"]]["events"] += 1
            if baseline.status == "SOURCE_PARSED":
                totals["baseline_complete"] += 1
                by_family[source["family"]]["baseline_complete"] += 1
                continue

            totals["baseline_incomplete"] += 1
            by_family[source["family"]]["baseline_incomplete"] += 1
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

            structural_view = None
            if merged is None and rgrams:
                structural_view = parse_security_once(raw)
                candidate = parse_with_relative_rgram(
                    raw, structural_view, rgrams
                )
                merged = merge_residual_hypothesis(baseline, candidate)
                if merged is not None:
                    chosen = "rgram"

            if merged is None:
                numeric_candidate = parse_leading_numeric_slots(raw, numeric)
                partial = augment_partial_with_numeric_prefix(
                    baseline, numeric_candidate
                )
                if partial is not None:
                    baseline_spans = {
                        (
                            span.path,
                            span.source_segments,
                            span.start_byte,
                            span.end_byte,
                        )
                        for span in baseline.value_spans
                    }
                    partial_spans = {
                        (
                            span.path,
                            span.source_segments,
                            span.start_byte,
                            span.end_byte,
                        )
                        for span in partial.value_spans
                    }
                    if partial.raw != baseline.raw:
                        partial_raw_mismatch += 1
                    elif not baseline_spans <= partial_spans:
                        partial_span_loss += 1
                    else:
                        gain = (
                            len(partial.value_spans)
                            - len(baseline.value_spans)
                        )
                        partial_augmented_events += 1
                        partial_source_span_gain += gain
                        totals["partial_augmented_events"] += 1
                        totals["numeric_prefix_partial_events"] += 1
                        totals["partial_source_span_gain"] += gain
                        by_family[source["family"]][
                            "partial_augmented_events"
                        ] += 1
                        by_family[source["family"]][
                            "numeric_prefix_partial_events"
                        ] += 1
                        by_family[source["family"]][
                            "partial_source_span_gain"
                        ] += gain
                continue

            baseline_spans = {
                (span.path, span.source_segments, span.start_byte, span.end_byte)
                for span in baseline.value_spans
            }
            merged_spans = {
                (span.path, span.source_segments, span.start_byte, span.end_byte)
                for span in merged.value_spans
            }
            if baseline.raw != merged.raw:
                promotion_raw_mismatch += 1
                continue
            if not baseline_spans <= merged_spans:
                promotion_span_loss += 1
                continue
            promotion_span_preserved += 1

            totals["promotions"] += 1
            totals[f"{chosen}_promotions"] += 1
            by_family[source["family"]]["promotions"] += 1
            by_family[source["family"]][f"{chosen}_promotions"] += 1
            span_gain += len(merged.value_spans) - len(baseline.value_spans)
            residual_reduction += baseline.residual_bytes - merged.residual_bytes

            if structural_view is None:
                structural_view = parse_security_once(raw)
            for mutated in _mutations(
                raw, chosen, delimited, templates, rgrams, structural_view
            ):
                mutation_attempts += 1
                mutated_baseline = parse_security_multipass(mutated)
                mutated_candidate = (
                    parse_with_hypothesis(mutated, delimited)
                    if chosen == "delimited"
                    else parse_with_event_template(mutated, templates)
                    if chosen == "template"
                    else parse_with_relative_rgram(
                        mutated,
                        parse_security_once(mutated),
                        rgrams,
                    )
                )
                mutated_merged = merge_residual_hypothesis(
                    mutated_baseline, mutated_candidate
                )
                if mutated_merged is not None:
                    mutation_false_complete += 1

    return {
        "seed": seed,
        "totals": dict(totals),
        "promoted_source_span_gain": span_gain,
        "promoted_residual_byte_reduction": residual_reduction,
        "partial_recovery": {
            "augmented_events": partial_augmented_events,
            "source_span_gain": partial_source_span_gain,
            "baseline_span_loss": partial_span_loss,
            "raw_mismatch": partial_raw_mismatch,
            "status_policy": "PARTIAL remains PARTIAL",
        },
        "promotion_safety": {
            "accepted_promotions_with_all_baseline_spans_preserved":
                promotion_span_preserved,
            "baseline_span_loss": promotion_span_loss,
            "raw_mismatch": promotion_raw_mismatch,
        },
        "mutation_safety": {
            "attempts": mutation_attempts,
            "false_complete": mutation_false_complete,
        },
        "by_family": {
            key: dict(value) for key, value in sorted(by_family.items())
        },
    }


def run() -> dict:
    splits = [run_seed(seed) for seed in SEEDS]
    aggregate = Counter()
    family_promotions = Counter()
    family_partial = Counter()
    mutation_attempts = 0
    mutation_false_complete = 0
    promotion_span_preserved = 0
    promotion_span_loss = 0
    promotion_raw_mismatch = 0
    partial_augmented_events = 0
    partial_source_span_gain = 0
    partial_span_loss = 0
    partial_raw_mismatch = 0
    for result in splits:
        aggregate.update(result["totals"])
        mutation_attempts += result["mutation_safety"]["attempts"]
        mutation_false_complete += result["mutation_safety"]["false_complete"]
        promotion_span_preserved += result["promotion_safety"][
            "accepted_promotions_with_all_baseline_spans_preserved"
        ]
        promotion_span_loss += result["promotion_safety"]["baseline_span_loss"]
        promotion_raw_mismatch += result["promotion_safety"]["raw_mismatch"]
        partial_augmented_events += result["partial_recovery"]["augmented_events"]
        partial_source_span_gain += result["partial_recovery"]["source_span_gain"]
        partial_span_loss += result["partial_recovery"]["baseline_span_loss"]
        partial_raw_mismatch += result["partial_recovery"]["raw_mismatch"]
        for family, metrics in result["by_family"].items():
            family_promotions[family] += metrics.get("promotions", 0)
            family_partial[family] += metrics.get("partial_augmented_events", 0)
    output = {
        "contract": "parser-studio.poc.structural-hypothesis-security-multisplit.v4",
        "scope": "SECURITY_PRODUCTS_ONLY",
        "split_count": len(splits),
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "raw_values_published": False,
        "splits": splits,
        "aggregate_totals": dict(aggregate),
        "aggregate_family_promotions": dict(sorted(family_promotions.items())),
        "aggregate_family_partial_recovery": dict(sorted(family_partial.items())),
        "aggregate_partial_recovery": {
            "augmented_events": partial_augmented_events,
            "source_span_gain": partial_source_span_gain,
            "baseline_span_loss": partial_span_loss,
            "raw_mismatch": partial_raw_mismatch,
            "status_policy": "PARTIAL remains PARTIAL",
        },
        "aggregate_promotion_safety": {
            "accepted_promotions_with_all_baseline_spans_preserved":
                promotion_span_preserved,
            "baseline_span_loss": promotion_span_loss,
            "raw_mismatch": promotion_raw_mismatch,
        },
        "aggregate_mutation_safety": {
            "attempts": mutation_attempts,
            "false_complete": mutation_false_complete,
        },
    }
    SUMMARY.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", "utf8")
    return output


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
