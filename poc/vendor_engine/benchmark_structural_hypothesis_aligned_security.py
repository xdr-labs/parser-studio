"""Broad security-only abstention/regression benchmark for aligned residual atoms.

This benchmark measures whether the batch-learned partial augmentation fires
outside the independently validated target grammar. Raw values are never
serialized.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from benchmark_structural_hypothesis_security import (
    LOCAL_CACHE,
    _events,
    _files,
    _split,
)
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    augment_with_aligned_residual_atoms,
    learn_aligned_residual_hypotheses,
)

BASE = Path(__file__).resolve().parent
OUT = BASE / "structural-hypothesis-aligned-security-summary.json"

EXTRAS = {
    "barracuda_waf_access.log": ("WAF", "barracuda_waf"),
    "barracuda_waf_audit.log": ("WAF", "barracuda_waf"),
    "barracuda_waf_network_firewall.log": ("WAF", "barracuda_waf"),
    "barracuda_waf_system.log": ("WAF", "barracuda_waf"),
    "barracuda_waf_web_firewall.log": ("WAF", "barracuda_waf"),
    "barracuda_cgf_firewall.log": ("NGFW", "barracuda_cloudgen_firewall"),
    "barracuda_cgf_threat.log": ("NGFW", "barracuda_cloudgen_firewall"),
    "barracuda_cgf_web.log": ("SWG", "barracuda_cloudgen_firewall"),
    "watchguard_alarm.log": ("NGFW", "watchguard"),
    "watchguard_diagnostic.log": ("NGFW", "watchguard"),
    "watchguard_event.log": ("NGFW", "watchguard"),
    "watchguard_traffic.log": ("NGFW", "watchguard"),
    "snort_fast.log": ("IDS_IPS", "snort"),
    "snort_full.log": ("IDS_IPS", "snort"),
    "snort_syslog.log": ("IDS_IPS", "snort"),
    "snort_pfsense.log": ("IDS_IPS", "snort"),
    "snort_csv.log": ("IDS_IPS", "snort"),
}


def _sources() -> list[dict[str, str]]:
    rows = list(_files())
    for name, (category, family) in EXTRAS.items():
        path = LOCAL_CACHE / name
        if path.exists():
            rows.append(
                {
                    "category": category,
                    "family": family,
                    "path": str(path),
                }
            )
    return rows


def _identity(event) -> set[tuple[str, tuple | None, int, int]]:
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def run() -> dict:
    totals = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    by_category: dict[str, Counter] = defaultdict(Counter)
    per_file = []

    for source in _sources():
        path = Path(source["path"])
        if not path.exists():
            continue
        rows = _events(path)
        if not rows:
            continue
        train, holdout = _split(rows)
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
            if not before <= after:
                metrics["baseline_span_loss_events"] += 1
            if augmented.status != baseline.status:
                metrics["status_changed_events"] += 1
            additions = after - before
            if additions:
                metrics["augmented_events"] += 1
                metrics["added_spans"] += len(additions)

        totals.update(metrics)
        by_family[source["family"]].update(metrics)
        by_category[source["category"]].update(metrics)
        per_file.append(
            {
                "category": source["category"],
                "family": source["family"],
                "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "event_count": len(rows),
                "train_count": len(train),
                "holdout_count": len(holdout),
                "hypothesis_count": len(hypotheses),
                "metrics": dict(metrics),
            }
        )

    augmented_families = sorted(
        family
        for family, metrics in by_family.items()
        if metrics["augmented_events"]
    )
    result = {
        "contract": "parser-studio.poc.aligned-residual-security-broad.v1",
        "scope": "SECURITY_PRODUCTS_ONLY",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "learner_vendor_identity_used": False,
        "semantic_mapping_scored": False,
        "raw_values_published": False,
        "files": len(per_file),
        "families": sorted(by_family),
        "family_count": len(by_family),
        "categories": sorted(by_category),
        "totals": dict(totals),
        "augmented_families": augmented_families,
        "by_family": {
            key: dict(value) for key, value in sorted(by_family.items())
        },
        "by_category": {
            key: dict(value) for key, value in sorted(by_category.items())
        },
        "per_file": per_file,
        "acceptance": {
            "baseline_span_loss_zero": totals["baseline_span_loss_events"] == 0,
            "status_change_zero": totals["status_changed_events"] == 0,
        },
        "notes": [
            "Added spans are scored for correctness in family-specific independent reference benchmarks.",
            "No SOURCE_PARSED result is reinterpreted by this partial augmentation layer.",
            "An abstention is preferred to an unverified field.",
        ],
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
