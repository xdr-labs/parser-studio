"""Ablate pass depth vs beam width on security-log positive/development families."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from benchmark_funnel_beam_security import SEEDS, _events, _source_files, _split
from funnel_beam_poc import FunnelConfig, replay_training, run_funnel_event
from multipass_adjudicator import parse_security_multipass

BASE = Path(__file__).resolve().parent
OUT = BASE / "funnel-beam-ablation-summary.json"
TARGETS = {
    "cisco_secure_email",
    "snort",
    "sophos_utm",
    "netscout_sightline",
    "symantec_endpoint",
    "watchguard",
    "watchguard_firebox",
}
CONFIGS = {
    "one_pass_greedy": FunnelConfig(max_passes=1, beam_width=1),
    "multi_pass_greedy": FunnelConfig(max_passes=6, beam_width=1),
    "one_pass_beam4": FunnelConfig(max_passes=1, beam_width=4),
    "multi_pass_beam4": FunnelConfig(max_passes=6, beam_width=4),
}


def _claims(event):
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def _run_config(config: FunnelConfig) -> dict:
    totals = Counter()
    provenance = Counter()
    selected_sources = [
        (family, path)
        for family, path in _source_files()
        if family in TARGETS
    ]
    for seed in SEEDS:
        for family, path in selected_sources:
            rows = _events(path)
            if len(rows) < 4:
                continue
            train, holdout = _split(rows, seed)
            hypotheses, _, training_passes = replay_training(train, config=config)
            totals["training_replay_pass_sum"] += training_passes
            totals["source_splits"] += 1
            for raw in holdout:
                baseline = parse_security_multipass(raw)
                result = run_funnel_event(raw, hypotheses, config=config)
                selected = result.selected
                totals["events"] += 1
                totals["pass_sum"] += result.passes_run
                totals["max_pass_observed"] = max(
                    totals["max_pass_observed"], result.passes_run
                )
                before = _claims(baseline)
                after = _claims(selected)
                if baseline.raw != selected.raw:
                    totals["raw_mismatch"] += 1
                    continue
                if not before <= after:
                    totals["span_loss"] += 1
                    continue
                if baseline.status == "SOURCE_PARSED":
                    if (
                        baseline.vendor_fields != selected.vendor_fields
                        or baseline.value_spans != selected.value_spans
                        or baseline.issues != selected.issues
                        or baseline.unparsed != selected.unparsed
                    ):
                        totals["complete_divergence"] += 1
                    else:
                        totals["complete_exact_preserved"] += 1
                    continue
                gain = len(after - before)
                if gain:
                    totals["improved_events"] += 1
                    totals["added_spans"] += gain
                    for item in result.beam[0].provenance[1:]:
                        provenance[item] += 1
                    if selected.status == "SOURCE_PARSED":
                        totals["complete_promotions"] += 1
                    else:
                        totals["partial_improvements"] += 1
    return {
        "config": {
            "max_passes": config.max_passes,
            "beam_width": config.beam_width,
        },
        "totals": dict(totals),
        "provenance": dict(sorted(provenance.items())),
    }


def run() -> dict:
    results = {name: _run_config(config) for name, config in CONFIGS.items()}
    one = results["one_pass_greedy"]["totals"]
    mpg = results["multi_pass_greedy"]["totals"]
    opb = results["one_pass_beam4"]["totals"]
    full = results["multi_pass_beam4"]["totals"]
    result = {
        "contract": "parser-studio.poc.funnel-beam-ablation.v1",
        "scope": "SECURITY_POSITIVE_AND_DEVELOPMENT_FAMILIES",
        "raw_values_published": False,
        "results": results,
        "deltas": {
            "multi_pass_gain_over_one_pass_greedy": {
                "added_spans": mpg.get("added_spans", 0) - one.get("added_spans", 0),
                "improved_events": mpg.get("improved_events", 0) - one.get("improved_events", 0),
            },
            "beam4_gain_over_beam1_at_one_pass": {
                "added_spans": opb.get("added_spans", 0) - one.get("added_spans", 0),
                "improved_events": opb.get("improved_events", 0) - one.get("improved_events", 0),
            },
            "full_gain_over_multi_pass_greedy": {
                "added_spans": full.get("added_spans", 0) - mpg.get("added_spans", 0),
                "improved_events": full.get("improved_events", 0) - mpg.get("improved_events", 0),
            },
        },
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
