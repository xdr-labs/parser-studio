"""Third prospective security-only holdout for Structural Hypothesis PoC.

The source-file set was committed in
STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_3_20261015.json before raw fixture
content was downloaded or evaluated. The benchmark is value-free and includes
all currently qualified research primitives, including CSV-cell label
refinement. Small files are controls rather than disjoint generalization cases.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from multipass_adjudicator import parse_security_multipass, parse_security_once
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    augment_partial_with_extended_bsd_envelope,
    augment_partial_with_numeric_prefix,
    augment_partial_with_residual_typed_labels,
    learn_best_hypothesis,
    learn_csv_cell_label_hypotheses,
    learn_event_template_hypotheses,
    learn_extended_bsd_envelope_hypotheses,
    learn_leading_numeric_hypotheses,
    learn_relative_rgram_hypotheses,
    learn_residual_typed_label_hypotheses,
    merge_residual_hypothesis,
    parse_extended_bsd_envelope,
    parse_leading_numeric_slots,
    parse_with_event_template,
    parse_with_hypothesis,
    parse_with_relative_rgram,
    refine_csv_cell_labels,
)

BASE = Path(__file__).resolve().parent
MANIFEST = BASE / "STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_3_20261015.json"
CACHE = BASE / ".cache" / "structural_hypothesis_fresh_holdout_3"
OUT = BASE / "structural-hypothesis-fresh-security-holdout-3-summary.json"
SPLIT_SEED = "structural-hypothesis-fresh-security-holdout-v3"


def _events(path: Path) -> list[str]:
    return [line for line in path.read_text("utf8").splitlines() if line.strip()]


def _split(rows: list[str]) -> tuple[list[str], list[str]]:
    if len(rows) < 4:
        return rows, rows
    ordered = sorted(
        rows,
        key=lambda raw: hashlib.sha256(
            (SPLIT_SEED + "|" + raw).encode("utf8")
        ).hexdigest(),
    )
    count = max(3, min(len(rows) - 1, round(len(rows) * 0.65)))
    return ordered[:count], ordered[count:]


def _git_blob_sha(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode() + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _span_set(event):
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def run() -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text("utf8"))
    totals = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    learned = Counter()
    per_file = []
    verified_files = 0

    for item in manifest["files"]:
        path = CACHE / item["family"] / Path(item["path"]).name
        data = path.read_bytes()
        if _git_blob_sha(data) != item["blob_sha"]:
            raise ValueError("FRESH_HOLDOUT_3_BLOB_SHA_MISMATCH:" + item["path"])
        verified_files += 1
        rows = _events(path)
        train, holdout = _split(rows)
        train_events = [parse_security_multipass(raw) for raw in train]

        delimiter = learn_best_hypothesis(train)
        templates = learn_event_template_hypotheses(train)
        rgrams = learn_relative_rgram_hypotheses(
            [parse_security_once(raw) for raw in train]
        )
        numeric = learn_leading_numeric_hypotheses(train)
        csv_labels = learn_csv_cell_label_hypotheses(train_events)
        extended_bsd = learn_extended_bsd_envelope_hypotheses(train)
        typed_labels = learn_residual_typed_label_hypotheses(train_events)
        learned["delimited"] += int(delimiter is not None)
        learned["event_template"] += len(templates)
        learned["relative_rgram"] += len(rgrams)
        learned["numeric_prefix"] += len(numeric)
        learned["csv_cell_label"] += len(csv_labels)
        learned["extended_bsd"] += len(extended_bsd)
        learned["residual_typed_label"] += len(typed_labels)

        stats = Counter()
        for raw in holdout:
            baseline = parse_security_multipass(raw)
            assert_source_accounting(baseline)
            stats["events"] += 1
            totals["events"] += 1
            if baseline.status == "SOURCE_PARSED":
                stats["baseline_complete"] += 1
                totals["baseline_complete"] += 1
                continue

            stats["baseline_incomplete"] += 1
            totals["baseline_incomplete"] += 1
            merged = None
            kind = None

            if delimiter is not None:
                merged = merge_residual_hypothesis(
                    baseline, parse_with_hypothesis(raw, delimiter)
                )
                if merged is not None:
                    kind = "delimited"
            if merged is None and templates:
                merged = merge_residual_hypothesis(
                    baseline, parse_with_event_template(raw, templates)
                )
                if merged is not None:
                    kind = "event_template"
            if merged is None and rgrams:
                view = parse_security_once(raw)
                merged = merge_residual_hypothesis(
                    baseline, parse_with_relative_rgram(raw, view, rgrams)
                )
                if merged is not None:
                    kind = "relative_rgram"

            if merged is not None:
                before = _span_set(baseline)
                after = _span_set(merged)
                if baseline.raw != merged.raw:
                    stats["rejected_raw_mismatch"] += 1
                    totals["rejected_raw_mismatch"] += 1
                elif not before <= after:
                    stats["rejected_baseline_span_loss"] += 1
                    totals["rejected_baseline_span_loss"] += 1
                else:
                    gain = len(merged.value_spans) - len(baseline.value_spans)
                    stats["promotions"] += 1
                    stats[kind + "_promotions"] += 1
                    stats["promotion_span_gain"] += max(0, gain)
                    totals["promotions"] += 1
                    totals[kind + "_promotions"] += 1
                    totals["promotion_span_gain"] += max(0, gain)
                continue

            partial = augment_partial_with_numeric_prefix(
                baseline, parse_leading_numeric_slots(raw, numeric)
            )
            partial_kind = "numeric_prefix"
            if partial is None:
                partial = refine_csv_cell_labels(baseline, csv_labels)
                partial_kind = "csv_cell_label"
            if partial is None:
                partial = augment_partial_with_extended_bsd_envelope(
                    baseline,
                    parse_extended_bsd_envelope(raw, extended_bsd),
                )
                partial_kind = "extended_bsd"
            if partial is None:
                partial = augment_partial_with_residual_typed_labels(
                    baseline, typed_labels
                )
                partial_kind = "residual_typed_label"

            if partial is None:
                stats["abstentions"] += 1
                totals["abstentions"] += 1
                continue

            before = _span_set(baseline)
            after = _span_set(partial)
            if partial.raw != baseline.raw:
                stats["rejected_partial_raw_mismatch"] += 1
                totals["rejected_partial_raw_mismatch"] += 1
            elif not before <= after:
                stats["rejected_partial_span_loss"] += 1
                totals["rejected_partial_span_loss"] += 1
            else:
                gain = len(partial.value_spans) - len(baseline.value_spans)
                stats["partial_augmented_events"] += 1
                stats[partial_kind + "_partial_events"] += 1
                stats["partial_span_gain"] += max(0, gain)
                totals["partial_augmented_events"] += 1
                totals[partial_kind + "_partial_events"] += 1
                totals["partial_span_gain"] += max(0, gain)

        by_family[item["family"]].update(stats)
        per_file.append(
            {
                "family": item["family"],
                "category": item["category"],
                "source_path": item["path"],
                "source_events": len(rows),
                "train_events": len(train),
                "evaluation_events": len(holdout),
                "evaluation_is_disjoint": len(rows) >= 4,
                "learned_hypotheses": {
                    "delimited": int(delimiter is not None),
                    "event_template": len(templates),
                    "relative_rgram": len(rgrams),
                    "numeric_prefix": len(numeric),
                    "csv_cell_label": len(csv_labels),
                    "extended_bsd": len(extended_bsd),
                    "residual_typed_label": len(typed_labels),
                },
                "metrics": dict(stats),
            }
        )

    result = {
        "contract": "parser-studio.poc.structural-hypothesis-fresh-security-holdout-3-result.v1",
        "scope": "SECURITY_PRODUCTS_ONLY_FRESH_HOLDOUT_3",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "upstream_repository": manifest["upstream_repository"],
        "upstream_revision": manifest["upstream_revision"],
        "frozen_manifest_file_set_sha256": manifest["file_set_sha256"],
        "verified_git_blob_files": verified_files,
        "product_vendor_identity_used_by_learner": False,
        "semantic_mapping_scored": False,
        "raw_values_published": False,
        "split_seed": SPLIT_SEED,
        "totals": dict(totals),
        "learned_hypothesis_counts": dict(learned),
        "by_family": {
            key: dict(value) for key, value in sorted(by_family.items())
        },
        "per_file": per_file,
        "result": (
            "ABSTENTION_ONLY"
            if totals["promotions"] == 0
            and totals["partial_augmented_events"] == 0
            else "CANDIDATE_GAIN_PRESENT"
        ),
        "interpretation": [
            "The file set was frozen and committed before raw content acquisition.",
            "No admission rule was weakened after observing the third holdout.",
            "Development-only Symantec/NETSCOUT CSV-label gains are not reused as prospective evidence.",
            "Zero gain is retained as negative generalization evidence rather than converted into vendor-specific exceptions.",
        ],
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
