"""Security-product-only benchmark for the bounded Funnel/Beam Auto Parser PoC.

Raw log values are never serialized. Training and evaluation are disjoint for
files with at least four logical events. Small files are reported as controls
but excluded from learned-gain totals.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from funnel_beam_poc import FunnelConfig, replay_training, run_funnel_event
from multipass_adjudicator import parse_security_multipass
from security_framing import MAX_BATCH_BYTES, parse_security_batch
from source_parse import assert_source_accounting

BASE = Path(__file__).resolve().parent
SUMMARY = BASE / "funnel-beam-security-poc-summary.json"
CONFIG = FunnelConfig(max_passes=6, beam_width=4)


def _module_sha256(name: str) -> str:
    return hashlib.sha256((BASE / name).read_bytes()).hexdigest()


SEEDS = ("funnel-a", "funnel-b", "funnel-c")

RESEARCH_CACHE = Path(
    "/home/aella/parser-studio-structural-hypothesis-poc-20261015/"
    "poc/vendor_engine/.cache"
)
ENGINE_CACHE = Path(
    "/home/aella/parser-studio-engine-poc-20261013/poc/vendor_engine/.cache"
)
POSTFREEZE = Path(
    "/home/aella/parser-studio-generic-structural-landing-20261015/"
    "poc/vendor_engine/.cache/generic_structural_postfreeze_074b90e"
)


def _source_files() -> list[tuple[str, Path]]:
    rows: list[tuple[str, Path]] = []

    explicit = {
        "aws_waf": [ENGINE_CACHE / "security_sources/aws_waf.raw"],
        "suricata": [
            ENGINE_CACHE / "security_sources/suricata_alert.raw",
            ENGINE_CACHE / "security_sources/suricata_v6.raw",
        ],
        "trellix_edr": [ENGINE_CACHE / "trellix_edr.raw"],
        "trellix_epo": [ENGINE_CACHE / "trellix_epo.raw"],
        "trend_vision": [ENGINE_CACHE / "trend_vision.raw"],
        "fortigate": [ENGINE_CACHE / "fortinet_traffic.raw"],
        "panw": [ENGINE_CACHE / "palo_threat.raw"],
    }
    for family, paths in explicit.items():
        for path in paths:
            if path.exists():
                rows.append((family, path))

    security_cache = RESEARCH_CACHE / "structural_hypothesis_security"
    if security_cache.exists():
        for path in sorted(security_cache.glob("*.log")):
            family = path.stem.split("_")[0]
            # Preserve known compound family identities.
            name = path.name
            for prefix, mapped in (
                ("cisco_secure_email", "cisco_secure_email"),
                ("cisco_asa", "cisco_asa"),
                ("sentinel_one", "sentinel_one"),
                ("crowdstrike", "crowdstrike"),
                ("darktrace", "darktrace"),
                ("extrahop", "extrahop"),
                ("zscaler", "zscaler_zia"),
                ("checkpoint", "checkpoint"),
                ("snort", "snort"),
                ("zeek", "zeek"),
            ):
                if name.startswith(prefix):
                    family = mapped
                    break
            rows.append((family, path))

    for root in (
        RESEARCH_CACHE / "structural_hypothesis_fresh_holdout",
        RESEARCH_CACHE / "structural_hypothesis_fresh_holdout_2",
        RESEARCH_CACHE / "structural_hypothesis_fresh_holdout_3",
        POSTFREEZE,
    ):
        if not root.exists():
            continue
        for path in sorted(root.glob("*/*.log")):
            rows.append((path.parent.name, path))

    seen = set()
    out = []
    for family, path in rows:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append((family, path))
    return out


def _events(path: Path) -> list[str]:
    text = path.read_text("utf8")
    if not text.strip():
        return []
    encoded = text.encode("utf8")
    if len(encoded) <= MAX_BATCH_BYTES:
        try:
            batch = parse_security_batch(
                text,
                max_events=10000,
                max_bytes=max(1, len(encoded)),
                parser=parse_security_multipass,
            )
            rows = [frame.raw for frame in batch.frames if frame.raw.strip()]
            if rows:
                return rows
        except (ValueError, TypeError, AssertionError):
            pass
    return [line for line in text.splitlines() if line.strip()]


def _split(rows: list[str], seed: str) -> tuple[list[str], list[str]]:
    ordered = sorted(
        rows,
        key=lambda raw: hashlib.sha256((seed + "|" + raw).encode("utf8")).hexdigest(),
    )
    train_count = max(3, min(len(rows) - 1, round(len(rows) * 0.65)))
    return ordered[:train_count], ordered[train_count:]


def _claims(event):
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def _mutations(raw: str) -> list[str]:
    if len(raw) < 8:
        return [raw + "\x00"]
    a = max(1, int(len(raw) * 0.60))
    b = max(1, int(len(raw) * 0.80))
    left = max(1, int(len(raw) * 0.45))
    right = min(len(raw) - 1, max(left + 1, int(len(raw) * 0.55)))
    candidates = [
        raw[:a],
        raw[:b],
        raw[:left] + raw[right:],
        raw[: len(raw) // 2] + "\x00" + raw[len(raw) // 2 :],
    ]
    return list(dict.fromkeys(item for item in candidates if item != raw))


def _status_bucket(prefix: str, status: str) -> str:
    return prefix + "_" + status.lower()


def run_seed(seed: str, source_files=None) -> dict:
    totals = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    provenance = Counter()
    pass_hist = Counter()
    replay_hist = Counter()
    small_controls = Counter()

    selected_sources = _source_files() if source_files is None else list(source_files)
    for family, path in selected_sources:
        rows = _events(path)
        if not rows:
            continue
        totals["source_files_seen"] += 1
        by_family[family]["source_files_seen"] += 1

        if len(rows) < 4:
            # No train/eval leakage: do not learn from tiny files.
            for raw in rows:
                baseline = parse_security_multipass(raw)
                assert_source_accounting(baseline)
                totals["small_control_events"] += 1
                small_controls[baseline.status] += 1
            continue

        train, holdout = _split(rows, seed)
        hypotheses, _train_events, replay_passes = replay_training(
            train, config=CONFIG
        )
        replay_hist[replay_passes] += 1
        totals["train_events"] += len(train)
        totals["eval_events"] += len(holdout)
        by_family[family]["eval_events"] += len(holdout)

        for raw in holdout:
            baseline = parse_security_multipass(raw)
            result = run_funnel_event(raw, hypotheses, config=CONFIG)
            selected = result.selected
            assert_source_accounting(baseline)
            assert_source_accounting(selected)

            totals[_status_bucket("baseline", baseline.status)] += 1
            totals[_status_bucket("funnel", selected.status)] += 1
            by_family[family][_status_bucket("baseline", baseline.status)] += 1
            by_family[family][_status_bucket("funnel", selected.status)] += 1
            pass_hist[result.passes_run] += 1
            if result.stopped_no_improvement:
                totals["stopped_no_improvement"] += 1

            base_claims = _claims(baseline)
            selected_claims = _claims(selected)
            if baseline.raw != selected.raw:
                totals["raw_mismatch"] += 1
                by_family[family]["raw_mismatch"] += 1
                continue
            if not base_claims <= selected_claims:
                totals["baseline_span_loss"] += 1
                by_family[family]["baseline_span_loss"] += 1
                continue

            if baseline.status == "SOURCE_PARSED":
                if (
                    baseline.vendor_fields != selected.vendor_fields
                    or baseline.value_spans != selected.value_spans
                    or baseline.issues != selected.issues
                    or baseline.unparsed != selected.unparsed
                ):
                    totals["baseline_complete_divergence"] += 1
                    by_family[family]["baseline_complete_divergence"] += 1
                else:
                    totals["baseline_complete_exact_preserved"] += 1
                continue

            added = len(selected_claims - base_claims)
            residual_reduction = max(
                0, baseline.residual_bytes - selected.residual_bytes
            )
            if added:
                totals["improved_events"] += 1
                totals["added_spans"] += added
                totals["residual_bytes_reduced"] += residual_reduction
                by_family[family]["improved_events"] += 1
                by_family[family]["added_spans"] += added
                by_family[family]["residual_bytes_reduced"] += residual_reduction
                for item in result.beam[0].provenance[1:]:
                    provenance[item] += 1
                    by_family[family]["prov:" + item] += 1

            if baseline.status != "SOURCE_PARSED" and selected.status == "SOURCE_PARSED":
                totals["complete_promotions"] += 1
                by_family[family]["complete_promotions"] += 1
                for mutated in _mutations(raw):
                    mutated_base = parse_security_multipass(mutated)
                    mutated_result = run_funnel_event(
                        mutated, hypotheses, config=CONFIG
                    )
                    totals["mutation_attempts"] += 1
                    if (
                        mutated_base.status != "SOURCE_PARSED"
                        and mutated_result.selected.status == "SOURCE_PARSED"
                    ):
                        totals["mutation_false_complete"] += 1
                        by_family[family]["mutation_false_complete"] += 1
            elif added:
                totals["partial_improvements"] += 1
                by_family[family]["partial_improvements"] += 1

    return {
        "seed": seed,
        "totals": dict(totals),
        "provenance": dict(sorted(provenance.items())),
        "pass_histogram": {str(k): v for k, v in sorted(pass_hist.items())},
        "training_replay_pass_histogram": {
            str(k): v for k, v in sorted(replay_hist.items())
        },
        "small_control_status": dict(sorted(small_controls.items())),
        "by_family": {
            family: dict(metrics)
            for family, metrics in sorted(by_family.items())
        },
    }


def run() -> dict:
    splits = [run_seed(seed) for seed in SEEDS]
    aggregate = Counter()
    provenance = Counter()
    family = defaultdict(Counter)
    max_pass = 0
    for split in splits:
        aggregate.update(split["totals"])
        provenance.update(split["provenance"])
        if split["pass_histogram"]:
            max_pass = max(max_pass, *(int(k) for k in split["pass_histogram"]))
        for name, metrics in split["by_family"].items():
            family[name].update(metrics)

    output = {
        "contract": "parser-studio.poc.funnel-beam-security.v1",
        "scope": "SECURITY_PRODUCTS_ONLY",
        "product_baseline_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "funnel_core_sha256": _module_sha256("funnel_beam_poc.py"),
        "structural_hypothesis_sha256": _module_sha256("structural_hypothesis_poc.py"),
        "split_count": len(splits),
        "max_passes": CONFIG.max_passes,
        "beam_width": CONFIG.beam_width,
        "runtime_ranked": False,
        "evaluation_feedback_into_training": False,
        "raw_values_published": False,
        "aggregate": dict(aggregate),
        "aggregate_provenance": dict(sorted(provenance.items())),
        "max_pass_observed": max_pass,
        "aggregate_by_family": {
            name: dict(metrics) for name, metrics in sorted(family.items())
        },
        "splits": splits,
        "decision_policy": {
            "baseline_complete_must_be_exact": True,
            "baseline_claim_loss_allowed": False,
            "partial_recovery_may_certify_complete": False,
            "complete_promotion_requires_strict_complete_hypothesis": True,
            "stop_when_no_new_beam_state": True,
        },
    }
    SUMMARY.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    return output


if __name__ == "__main__":
    result = run()
    print(json.dumps({
        "aggregate": result["aggregate"],
        "provenance": result["aggregate_provenance"],
        "max_pass_observed": result["max_pass_observed"],
    }, indent=2, sort_keys=True))
