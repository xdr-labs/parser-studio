"""Security-product-only benchmark for Structural Hypothesis PoC v1.

No raw log values are written to the summary.  Inputs stay in ignored/local
research caches.  The benchmark deliberately includes already-well-parsed WAF,
IDS/IPS, EDR and NDR telemetry as no-regression controls.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Iterable

from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting
from structural_hypothesis_poc import (
    delete_required_delimited_anchors,
    delete_required_template_anchor,
    learn_best_hypothesis,
    learn_event_template_hypotheses,
    merge_residual_hypothesis,
    parse_with_event_template,
    parse_with_hypothesis,
)

BASE = Path(__file__).resolve().parent
LOCAL_CACHE = BASE / ".cache" / "structural_hypothesis_security"
ENGINE_CACHE = Path(
    "/home/aella/parser-studio-engine-poc-20261013/poc/vendor_engine/.cache"
)
POSTFREEZE = Path(
    "/home/aella/parser-studio-generic-structural-landing-20261015/"
    "poc/vendor_engine/.cache/generic_structural_postfreeze_074b90e"
)
SUMMARY = BASE / "structural-hypothesis-security-poc-summary.json"


def _files() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = [
        {"category": "WAF", "family": "aws_waf", "path": str(ENGINE_CACHE / "security_sources/aws_waf.raw")},
        {"category": "IDS_IPS_NDR", "family": "suricata", "path": str(ENGINE_CACHE / "security_sources/suricata_alert.raw")},
        {"category": "IDS_IPS_NDR", "family": "suricata", "path": str(ENGINE_CACHE / "security_sources/suricata_v6.raw")},
        {"category": "EDR", "family": "trellix_edr", "path": str(ENGINE_CACHE / "trellix_edr.raw")},
        {"category": "EDR", "family": "trellix_epo", "path": str(ENGINE_CACHE / "trellix_epo.raw")},
        {"category": "EDR_XDR", "family": "trend_vision", "path": str(ENGINE_CACHE / "trend_vision.raw")},
        {"category": "NGFW", "family": "fortigate", "path": str(ENGINE_CACHE / "fortinet_traffic.raw")},
        {"category": "NGFW", "family": "panw", "path": str(ENGINE_CACHE / "palo_threat.raw")},
        {"category": "NDR_NETWORK_TELEMETRY", "family": "zeek", "path": str(LOCAL_CACHE / "zeek_conn.log")},
        {"category": "NDR_NETWORK_TELEMETRY", "family": "zeek", "path": str(LOCAL_CACHE / "zeek_notice.log")},
        {"category": "NDR", "family": "darktrace", "path": str(LOCAL_CACHE / "darktrace_model.log")},
        {"category": "NDR", "family": "darktrace", "path": str(LOCAL_CACHE / "darktrace_ai.log")},
        {"category": "NDR", "family": "extrahop", "path": str(LOCAL_CACHE / "extrahop_detection.log")},
        {"category": "NDR", "family": "extrahop", "path": str(LOCAL_CACHE / "extrahop_investigation.log")},
        {"category": "SWG_CLOUD_FIREWALL", "family": "zscaler_zia", "path": str(LOCAL_CACHE / "zscaler_firewall.log")},
        {"category": "SWG_CLOUD_FIREWALL", "family": "zscaler_zia", "path": str(LOCAL_CACHE / "zscaler_firewall_http.log")},
        {"category": "EDR", "family": "sentinel_one", "path": str(LOCAL_CACHE / "sentinel_one_threat.log")},
        {"category": "EDR", "family": "crowdstrike", "path": str(LOCAL_CACHE / "crowdstrike_alert.log")},
        {"category": "EDR", "family": "crowdstrike", "path": str(LOCAL_CACHE / "crowdstrike_automated_lead.log")},
        {"category": "NGFW", "family": "checkpoint", "path": str(LOCAL_CACHE / "checkpoint_r81x.log")},
        {"category": "NGFW_VPN", "family": "cisco_asa", "path": str(LOCAL_CACHE / "cisco_asa_anyconnect.log")},
        {"category": "NGFW_VPN", "family": "cisco_asa", "path": str(LOCAL_CACHE / "cisco_asa_fix.log")},
    ]
    extra = {
        "f5_bigip": "WAF_NGFW",
        "cisco_ise": "NAC_IDENTITY_SECURITY",
        "juniper_srx": "NGFW_IDS_IPS",
        "sophos_utm": "UTM",
        "sophos_xg": "NGFW_UTM",
    }
    for family, category in extra.items():
        root = POSTFREEZE / family
        if not root.exists():
            continue
        for path in sorted(root.glob("*.log")):
            rows.append({"category": category, "family": family, "path": str(path)})
    return rows


def _events(path: Path) -> list[str]:
    text = path.read_text("utf8")
    return [line for line in text.splitlines() if line.strip()]


def _split(rows: list[str]) -> tuple[list[str], list[str]]:
    if len(rows) < 4:
        return rows, rows
    ordered = sorted(
        rows,
        key=lambda raw: hashlib.sha256(
            ("structural-hypothesis-security-v1|" + raw).encode("utf8")
        ).hexdigest(),
    )
    train_count = max(3, min(len(rows) - 1, round(len(rows) * 0.65)))
    return ordered[:train_count], ordered[train_count:]


def _hypothesis_metadata(hypothesis):
    if hypothesis is None:
        return None
    return {
        "delimiter": hypothesis.delimiter,
        "stable_anchor_count": len(hypothesis.stable_anchors),
        "has_first_anchor": hypothesis.first_anchor is not None,
        "min_anchor_hits": hypothesis.min_anchor_hits,
        "terminal_anchor_count": len(hypothesis.terminal_anchors),
        "training_samples": hypothesis.training_samples,
        "confidence": round(hypothesis.confidence, 6),
    }


def run() -> dict:
    per_file = []
    totals = Counter()
    by_category: dict[str, Counter] = defaultdict(Counter)
    by_family: dict[str, Counter] = defaultdict(Counter)
    mutation_false_complete = 0
    mutation_attempts = 0
    promoted_span_gain = 0
    promoted_residual_reduction = 0
    promoted_baseline_spans_preserved = 0
    promoted_baseline_span_loss = 0
    promoted_raw_mismatch = 0
    disjoint_evaluation_events = 0
    small_file_control_events = 0
    file_sources = _files()

    for source in file_sources:
        path = Path(source["path"])
        if not path.exists():
            continue
        rows = _events(path)
        if not rows:
            continue
        train, holdout = _split(rows)
        if len(rows) < 4:
            small_file_control_events += len(holdout)
        else:
            disjoint_evaluation_events += len(holdout)
        hypothesis = learn_best_hypothesis(train)
        template_hypotheses = learn_event_template_hypotheses(train)
        stats = Counter()
        for raw in holdout:
            baseline = parse_security_multipass(raw)
            assert_source_accounting(baseline)
            stats["events"] += 1
            totals["events"] += 1
            if baseline.status == "SOURCE_PARSED":
                stats["baseline_complete"] += 1
                totals["baseline_complete"] += 1
                # Product rule: complete records are never reinterpreted.
                continue

            stats["baseline_incomplete"] += 1
            totals["baseline_incomplete"] += 1

            merged = None
            chosen_kind = None
            if hypothesis is not None:
                stats["delimited_attempts"] += 1
                totals["delimited_attempts"] += 1
                candidate = parse_with_hypothesis(raw, hypothesis)
                if candidate is not None:
                    assert_source_accounting(candidate)
                    merged = merge_residual_hypothesis(baseline, candidate)
                    if merged is not None:
                        chosen_kind = "delimited"

            if merged is None and template_hypotheses:
                template_candidate = parse_with_event_template(
                    raw, template_hypotheses
                )
                if template_candidate is not None:
                    stats["template_attempts"] += 1
                    totals["template_attempts"] += 1
                    assert_source_accounting(template_candidate)
                    merged = merge_residual_hypothesis(
                        baseline, template_candidate
                    )
                    if merged is not None:
                        chosen_kind = "template"

            if merged is None:
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
                promoted_raw_mismatch += 1
                stats["safety_rejected_raw_mismatch"] += 1
                totals["safety_rejected_raw_mismatch"] += 1
                continue
            if not baseline_spans <= merged_spans:
                promoted_baseline_span_loss += 1
                stats["safety_rejected_span_loss"] += 1
                totals["safety_rejected_span_loss"] += 1
                continue
            promoted_baseline_spans_preserved += 1

            stats["hypothesis_attempts"] += 1
            totals["hypothesis_attempts"] += 1
            stats["promotions"] += 1
            totals["promotions"] += 1
            stats[f"{chosen_kind}_promotions"] += 1
            totals[f"{chosen_kind}_promotions"] += 1
            promoted_span_gain += max(
                0, len(merged.value_spans) - len(baseline.value_spans)
            )
            promoted_residual_reduction += max(
                0, baseline.residual_bytes - merged.residual_bytes
            )

            # Fail-closed mutation: the same product-style residual merge must
            # not certify truncation or NUL-corrupted input.
            structural_mutation = (
                delete_required_delimited_anchors(raw, hypothesis)
                if chosen_kind == "delimited"
                else delete_required_template_anchor(
                    raw, template_hypotheses
                )
            )
            mutations = [
                raw[: max(1, int(len(raw) * 0.60))],
                raw[: max(1, int(len(raw) * 0.80))],
                raw[max(1, int(len(raw) * 0.20)) :],
                raw[: max(1, len(raw) // 2)] + "\x00" + raw[len(raw) // 2 :],
            ]
            if structural_mutation is not None:
                mutations.append(structural_mutation)
            for mutated in mutations:
                mutation_attempts += 1
                mutated_baseline = parse_security_multipass(mutated)
                mutated_candidate = (
                    parse_with_hypothesis(mutated, hypothesis)
                    if chosen_kind == "delimited"
                    else parse_with_event_template(mutated, template_hypotheses)
                )
                mutated_merged = merge_residual_hypothesis(
                    mutated_baseline, mutated_candidate
                )
                if mutated_merged is not None and mutated_merged.status == "SOURCE_PARSED":
                    mutation_false_complete += 1

        row = {
            "category": source["category"],
            "family": source["family"],
            "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "event_count": len(rows),
            "train_count": len(train),
            "holdout_count": len(holdout),
            "hypothesis": _hypothesis_metadata(hypothesis),
            "template_hypotheses": {
                "count": len(template_hypotheses),
                "training_support_total": sum(
                    item.training_support
                    for item in template_hypotheses.values()
                ),
            },
            "metrics": dict(stats),
        }
        per_file.append(row)
        by_category[source["category"]].update(stats)
        by_family[source["family"]].update(stats)

    result = {
        "contract": "parser-studio.poc.structural-hypothesis-security.v1",
        "scope": "SECURITY_PRODUCTS_ONLY",
        "source_engine_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "additional_public_fixture_source": "elastic/integrations",
        "additional_public_fixture_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "product_vendor_identity_used_by_learner": False,
        "semantic_mapping_scored": False,
        "promotion_independent_vendor_gold_scored": False,
        "raw_values_published": False,
        "categories": sorted(by_category),
        "families": sorted(by_family),
        "files": len(per_file),
        "disjoint_evaluation_events": disjoint_evaluation_events,
        "small_file_no_regression_control_events": small_file_control_events,
        "totals": dict(totals),
        "promoted_source_span_gain": promoted_span_gain,
        "promoted_residual_byte_reduction": promoted_residual_reduction,
        "promotion_safety": {
            "accepted_promotions_with_all_baseline_spans_preserved":
                promoted_baseline_spans_preserved,
            "baseline_span_loss": promoted_baseline_span_loss,
            "raw_mismatch": promoted_raw_mismatch,
        },
        "mutation_safety": {
            "attempts": mutation_attempts,
            "false_complete": mutation_false_complete,
            "mutation_types": 5,
        },
        "by_category": {key: dict(value) for key, value in sorted(by_category.items())},
        "by_family": {key: dict(value) for key, value in sorted(by_family.items())},
        "per_file": per_file,
        "limitations": [
            "v2 learns delimiter/key-anchor and numeric-event-code template structure; it is not a general CFG learner.",
            "Promotion is structural evidence, not semantic field normalization evidence.",
            "Only existing incomplete events are eligible; prior SOURCE_PARSED records are never reinterpreted.",
            "The promoted holdouts do not yet have an independent vendor-native field/span oracle, so promotion is not product qualification.",
        ],
    }
    SUMMARY.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
