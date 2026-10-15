"""Prove Funnel keeps only previously independently validated positive spans.

The three reference summaries were produced by the closed Structural Hypothesis
PoC using pinned Elastic/vendor references. This benchmark reruns the exact
standalone primitives and requires the current Funnel to add the same byte
ranges, never more, on the same deterministic splits.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from funnel_beam_poc import FunnelConfig, replay_training, run_funnel_event
from multipass_adjudicator import parse_security_multipass, parse_security_once
from structural_hypothesis_poc import (
    augment_partial_with_numeric_prefix,
    learn_leading_numeric_hypotheses,
    learn_relative_rgram_hypotheses,
    merge_residual_hypothesis,
    parse_leading_numeric_slots,
    parse_with_relative_rgram,
)

BASE = Path(__file__).resolve().parent
CACHE = BASE / ".cache" / "structural_hypothesis_security"
POSTFREEZE = Path(
    "/home/aella/parser-studio-generic-structural-landing-20261015/"
    "poc/vendor_engine/.cache/generic_structural_postfreeze_074b90e"
)
CONFIG = FunnelConfig(max_passes=6, beam_width=4)
SEEDS = (
    "structural-hypothesis-security-ms-a",
    "structural-hypothesis-security-ms-b",
    "structural-hypothesis-security-ms-c",
)
OUT = BASE / "funnel-beam-reference-validation-summary.json"


def _module_sha256(name: str) -> str:
    return hashlib.sha256((BASE / name).read_bytes()).hexdigest()


def _events(path: Path) -> list[str]:
    return [line for line in path.read_text("utf8").splitlines() if line.strip()]


def _split(rows: list[str], seed: str) -> tuple[list[str], list[str]]:
    if len(rows) < 4:
        return rows, rows
    ordered = sorted(
        rows,
        key=lambda raw: hashlib.sha256((seed + "|" + raw).encode("utf8")).hexdigest(),
    )
    count = max(3, min(len(rows) - 1, round(len(rows) * 0.65)))
    return ordered[:count], ordered[count:]


def _ranges(event) -> set[tuple[int, int]]:
    return {(span.start_byte, span.end_byte) for span in event.value_spans}


def _added_ranges(baseline, candidate) -> set[tuple[int, int]]:
    return _ranges(candidate) - _ranges(baseline)


def _reference_count(filename: str) -> int:
    data = json.loads((BASE / filename).read_text("utf8"))
    metrics = data["aggregate_metrics"]
    if not data.get("all_added_spans_independently_validated"):
        raise ValueError("REFERENCE_NOT_INDEPENDENTLY_VALIDATED:" + filename)
    return int(metrics["independently_validated_spans"])


def _cisco() -> dict:
    rows = _events(CACHE / "cisco_secure_email_text_mail.log")
    metrics = Counter()
    for seed in SEEDS:
        train, holdout = _split(rows, seed)
        rgrams = learn_relative_rgram_hypotheses(
            [parse_security_once(raw) for raw in train]
        )
        funnel_hypotheses, _, _ = replay_training(train, config=CONFIG)
        for raw in holdout:
            baseline = parse_security_multipass(raw)
            if baseline.status == "SOURCE_PARSED":
                continue
            primitive = merge_residual_hypothesis(
                baseline,
                parse_with_relative_rgram(
                    raw, parse_security_once(raw), rgrams
                ),
            )
            funnel = run_funnel_event(raw, funnel_hypotheses, config=CONFIG).selected
            primitive_added = set() if primitive is None else _added_ranges(baseline, primitive)
            funnel_added = _added_ranges(baseline, funnel)
            if funnel_added:
                metrics["augmented_occurrences"] += 1
                metrics["funnel_added_spans"] += len(funnel_added)
                metrics["range_matches"] += len(funnel_added & primitive_added)
                metrics["range_extras"] += len(funnel_added - primitive_added)
                if funnel.status == "SOURCE_PARSED":
                    metrics["complete_promotions"] += 1
                else:
                    metrics["partial_retained"] += 1
    expected = _reference_count(
        "structural-hypothesis-cisco-reference-multisplit-summary.json"
    )
    metrics["prior_independently_validated_spans"] = expected
    return dict(metrics)


def _numeric(paths: list[Path], reference_summary: str) -> dict:
    metrics = Counter()
    for seed in SEEDS:
        for path in paths:
            rows = _events(path)
            train, holdout = _split(rows, seed)
            numeric = learn_leading_numeric_hypotheses(train)
            funnel_hypotheses, _, _ = replay_training(train, config=CONFIG)
            for raw in holdout:
                baseline = parse_security_multipass(raw)
                if baseline.status == "SOURCE_PARSED":
                    continue
                primitive = augment_partial_with_numeric_prefix(
                    baseline, parse_leading_numeric_slots(raw, numeric)
                )
                funnel = run_funnel_event(
                    raw, funnel_hypotheses, config=CONFIG
                ).selected
                primitive_added = set() if primitive is None else _added_ranges(
                    baseline, primitive
                )
                funnel_added = _added_ranges(baseline, funnel)
                if funnel_added:
                    metrics["augmented_occurrences"] += 1
                    metrics["funnel_added_spans"] += len(funnel_added)
                    metrics["range_matches"] += len(funnel_added & primitive_added)
                    metrics["range_extras"] += len(funnel_added - primitive_added)
                    if funnel.status == "SOURCE_PARSED":
                        metrics["unexpected_complete"] += 1
    metrics["prior_independently_validated_spans"] = _reference_count(reference_summary)
    return dict(metrics)


def run() -> dict:
    cisco = _cisco()
    snort = _numeric(
        [CACHE / "snort_fast.log"],
        "structural-hypothesis-snort-numeric-prefix-multisplit-summary.json",
    )
    sophos = _numeric(
        [
            POSTFREEZE / "sophos_utm" / "test-sophos-utm-dhcp.log",
            POSTFREEZE / "sophos_utm" / "test-sophos-utm-dns.log",
        ],
        "structural-hypothesis-sophos-numeric-prefix-multisplit-summary.json",
    )
    families = {
        "cisco_secure_email": cisco,
        "snort_ids_ips": snort,
        "sophos_utm": sophos,
    }
    total_added = sum(v.get("funnel_added_spans", 0) for v in families.values())
    total_matches = sum(v.get("range_matches", 0) for v in families.values())
    total_reference = sum(
        v.get("prior_independently_validated_spans", 0) for v in families.values()
    )
    total_extras = sum(v.get("range_extras", 0) for v in families.values())
    result = {
        "contract": "parser-studio.poc.funnel-beam-reference-validation.v2",
        "product_baseline_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "funnel_core_sha256": _module_sha256("funnel_beam_poc.py"),
        "structural_hypothesis_sha256": _module_sha256("structural_hypothesis_poc.py"),
        "raw_values_published": False,
        "families": families,
        "totals": {
            "funnel_added_spans": total_added,
            "matched_prior_independently_validated_ranges": total_matches,
            "prior_independently_validated_spans": total_reference,
            "extra_unvalidated_ranges": total_extras,
        },
        "all_funnel_positive_ranges_previously_independently_validated": (
            total_added == total_matches == total_reference and total_extras == 0
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
