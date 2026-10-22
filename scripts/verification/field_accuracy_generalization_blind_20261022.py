#!/usr/bin/env python3
"""ACC-2: frozen independent JSON field-oracle, zero raw/value disclosure.

The held-out oracle was sealed before the candidate was authored. This script
keeps the 177 unscorable sources OUT of precision/recall denominators.
Scores structural JSON field identity only, not source/destination semantics,
native parser compatibility or a manufacturer-wide confidence interval.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "multipass"))

from accuracy_shadow import choose_shadow
from bounded_funnel import FunnelConfig, FunnelHypotheses, run_funnel_batch, run_funnel_event
from multipass_contract import CandidateEvidence, candidate_from_event
from field_accuracy_shadow_poc import summarize

PINNED_PRIVATE_ORACLE_SHA256 = "1918c4da2e4c6b5dd5dd6381e976cc31fd82d337da4a25f32ce7f3eecbed2881"
EVIDENCE = CandidateEvidence(
    "acc2-independent-json", None, None,
    "HEURISTIC_RESIDUAL", False, "20261022-frozen-shadow",
)
NO_HYPOTHESES = FunnelHypotheses(None, {}, {}, {}, {}, {}, {})


def _pointer(segments: tuple | None) -> str | None:
    if segments is None:
        return None
    return "/" + "/".join(
        str(item).replace("~", "~0").replace("/", "~1") for item in segments
    )


def _typed_value_id(value: object) -> str:
    return type(value).__name__ + ":" + json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )


def _truth_claim(claim: dict) -> tuple:
    return (
        claim["path"], claim["value_start_byte"], claim["value_end_byte"],
        _typed_value_id(claim["value"]),
    )


def _prediction_claim(occurrence: object) -> tuple:
    return (
        _pointer(occurrence.source_segments),
        occurrence.start_byte,
        occurrence.end_byte,
        _typed_value_id(occurrence.value),
    )


def _compare(event: object, row: dict) -> dict:
    # Pinned independent Python JSON parser plus byte-tokenizer leaf truth.
    expected = Counter(map(_truth_claim, row["fields"]))
    actual = Counter(map(_prediction_claim, event.occurrences))
    tp = sum((expected & actual).values())
    fp = sum((actual - expected).values())
    fn = sum((expected - actual).values())
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "false_complete": event.completeness == "SOURCE_PARSED" and (fp > 0 or fn > 0),
    }


def _verified_oracle(path: Path, metadata: Path) -> tuple[list[dict], dict]:
    frozen_bytes = path.read_bytes()
    if sha256(frozen_bytes).hexdigest() != PINNED_PRIVATE_ORACLE_SHA256:
        raise ValueError("SEALED_ORACLE_SHA256_CHANGED")
    summary = json.loads(metadata.read_bytes())
    if summary.get("private_oracle_sha256") != PINNED_PRIVATE_ORACLE_SHA256:
        raise ValueError("INDEPENDENT_ORACLE_MANIFEST_MISMATCH")
    if summary.get("status") != "FROZEN_BEFORE_BASELINE_OR_CANDIDATE_SCORING":
        raise ValueError("ORACLE_NOT_FROZEN_BEFORE_CANDIDATE")
    if summary.get("candidate_access_to_sealed_truth") != "prohibited_until_candidate_frozen":
        raise ValueError("SEALED_HOLDOUT_POLICY_MISMATCH")
    rows = json.loads(frozen_bytes.decode("utf8", "strict"))
    if len(rows) != summary["all_events"]:
        raise ValueError("INDEPENDENT_RECORD_COUNT_MISMATCH")

    scorable = 0
    unscorable = 0
    field_count = 0
    for item in rows:
        source = item["raw"].encode("utf8")
        if len(source) > 65536:
            raise ValueError("INDEPENDENT_RECORD_LIMIT")
        if sha256(source).hexdigest() != item["raw_event_sha256"]:
            raise ValueError("INDEPENDENT_RECORD_HASH_MISMATCH")
        if item["split"] not in ("development", "sealed_holdout"):
            raise ValueError("INVALID_FROZEN_SPLIT")
        if item["oracle_status"] == "UNSCORABLE":
            unscorable += 1
            continue
        if item["oracle_status"] != "INDEPENDENT_JSON_BYTE_TRUTH" or item["format_hint"] != "json":
            raise ValueError("UNQUALIFIED_ORACLE")
        scorable += 1
        field_count += len(item["fields"])
        for claim in item["fields"]:
            a = claim["value_start_byte"]
            b = claim["value_end_byte"]
            if not 0 <= a <= b <= len(source):
                raise ValueError("INDEPENDENT_LEAF_RANGE_INVALID")
            try:
                source[:a].decode("utf8")
                source[:b].decode("utf8")
                value = json.loads(source[a:b].decode("utf8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise ValueError("INDEPENDENT_LEAF_NOT_JSON") from error
            if _typed_value_id(value) != _typed_value_id(claim["value"]):
                raise ValueError("INDEPENDENT_LEAF_VALUE_MISMATCH")
    if (
        scorable != summary["scorable_events"]
        or unscorable != summary["unscorable_events"]
        or field_count != summary["leaf_fields"]
    ):
        raise ValueError("FROZEN_MANIFEST_GOLDEN_COUNTS_MISMATCH")
    return rows, summary


def _percentile(samples: list[float], probability: float) -> float | None:
    if len(samples) < 30:
        return None
    ordered = sorted(samples)
    index = min(len(ordered) - 1, int(round(probability * (len(ordered) - 1))))
    return round(ordered[index], 4)


def score_holdout(oracle: Path, metadata: Path) -> dict:
    rows, manifest = _verified_oracle(oracle, metadata)
    metrics: dict[tuple[str, str], dict[str, list]] = defaultdict(
        lambda: {"product": [], "shadow": []}
    )
    pool_counts = Counter()
    statuses: dict[tuple[str, str], Counter] = defaultdict(Counter)
    times: dict[str, list[float]] = defaultdict(list)
    changes = 0
    rejected = 0
    unscorable = Counter()
    for row in rows:
        split = row["split"]
        family = row["family"]
        if row["oracle_status"] != "INDEPENDENT_JSON_BYTE_TRUTH":
            unscorable[(split, family)] += 1
            continue
        raw = row["raw"]
        t0 = perf_counter_ns()
        product_event = run_funnel_batch([raw]).selected[0]
        t1 = perf_counter_ns()
        # In JSON SOURCE_PARSED the no-loss/immutable fast path must not
        # branch into new structural recovery. Keep this pool fixed.
        baseline = candidate_from_event(product_event, EVIDENCE)
        exploration = run_funnel_event(
            raw, NO_HYPOTHESES, config=FunnelConfig(beam_width=4)
        )
        pool = [baseline]
        for beam in exploration.beam:
            claim = candidate_from_event(beam.event, EVIDENCE)
            if all(
                (claim.completeness, claim.occurrences, claim.issues) !=
                (prior.completeness, prior.occurrences, prior.issues)
                for prior in pool
            ):
                pool.append(claim)
        t2 = perf_counter_ns()
        decision = choose_shadow(raw, pool, baseline)
        t3 = perf_counter_ns()
        if decision.selected_index is None:
            raise ValueError("SHADOW_NO_VALID_CANDIDATE")
        selected = pool[decision.selected_index]
        if selected.completeness == "SOURCE_PARSED" and product_event.status != "SOURCE_PARSED":
            raise ValueError("SHADOW_FALSE_COMPLETE")
        if selected.occurrences != baseline.occurrences:
            changes += 1
        rejected += sum(not result.valid for result in decision.scores)
        pool_counts[len(pool)] += 1
        metrics[(split, family)]["product"].append(_compare(baseline, row))
        metrics[(split, family)]["shadow"].append(_compare(selected, row))
        statuses[(split, family)][product_event.status] += 1
        times["product_ms"].append((t1-t0) / 1e6)
        times["research_pool_ms"].append((t2-t1) / 1e6)
        times["shadow_score_ms"].append((t3-t2) / 1e6)
    per_split_family = {
        split + "/" + family: {
            "events": len(series["product"]),
            "product": summarize(series["product"]),
            "shadow": summarize(series["shadow"]),
            "statuses": dict(sorted(statuses[(split, family)].items())),
        }
        for (split, family), series in sorted(metrics.items())
    }
    per_split = {}
    for split in ("development", "sealed_holdout"):
        dev_rows = {
            mode: [x for (part, _), series in metrics.items() if part == split
                   for x in series[mode]]
            for mode in ("product", "shadow")
        }
        per_split[split] = {
            "scorable_events": len(dev_rows["product"]),
            "product": summarize(dev_rows["product"]),
            "shadow": summarize(dev_rows["shadow"]),
            "families": sorted(set(f for (part, f) in metrics if part == split)),
            "unscorable_events_excluded": sum(
                count for (part, _), count in unscorable.items() if part == split
            ),
        }
    return {
        "contract": "parser-studio.acc2.sealed-json-field-score.v0.1",
        "oracle_provenance": "FROZEN_INDEPENDENT_JSON_BYTE_TRUTH_NOT_VENDOR_SEMANTIC",
        "private_oracle_sha256": PINNED_PRIVATE_ORACLE_SHA256,
        "upstream_source_manifest_sha256": manifest["source_manifest_sha256"],
        "record_count": len(rows),
        "total_independently_scored_fields": manifest["leaf_fields"],
        "unscorable_excluded": manifest["unscorable_events"],
        "product_source_status_by_family": per_split_family,
        "per_split": per_split,
        "research_pool_sizes": {str(k): v for k, v in sorted(pool_counts.items())},
        "shadow_hard_rejections": rejected,
        "shadow_changed_field_claims": changes,
        "latency_ms": {
            mode: {
                "p50": _percentile(samples, 0.5),
                "p99": _percentile(samples, 0.99),
                "sample_count": len(samples),
            } for mode, samples in times.items()
        },
        "latency_scope": "ONE_PROCESS_LOCAL_MEASUREMENT_NOT_PRODUCTION_SLA",
        "sealed_holdout_not_used_for_weight_calibration": True,
        "manufacturer_wide_statistical_significance": "INSUFFICIENT_DISTINCT_MANUFACTURER_CLUSTERS",
        "normalization_and_role_accuracy": "NOT_SCORED",
        "product_runtime_modified": False,
        "original_source_values_printed": False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Score frozen independent JSON field oracles, digest only")
    p.add_argument("--oracle", type=Path, required=True)
    p.add_argument("--metadata", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = score_holdout(args.oracle, args.metadata)
    report = json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
