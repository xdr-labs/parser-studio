"""Re-evaluate frozen security-only holdouts with the Funnel/Beam PoC.

Raw values stay in ignored local caches. The committed manifests were frozen
before those raw files were acquired. Evaluation never feeds back into training.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from funnel_beam_poc import FunnelConfig, replay_training, run_funnel_event
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

BASE = Path(__file__).resolve().parent
CONFIG = FunnelConfig(max_passes=6, beam_width=4)
CASES = (
    (
        2,
        BASE / "STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_2_20261015.json",
        BASE / ".cache" / "structural_hypothesis_fresh_holdout_2",
        "structural-hypothesis-fresh-security-holdout-v2",
    ),
    (
        3,
        BASE / "STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_3_20261015.json",
        BASE / ".cache" / "structural_hypothesis_fresh_holdout_3",
        "structural-hypothesis-fresh-security-holdout-v3",
    ),
)
OUT = BASE / "funnel-beam-fresh-holdouts-summary.json"


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


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _claims(event):
    return {
        (span.path, span.source_segments, span.start_byte, span.end_byte)
        for span in event.value_spans
    }


def _evaluate(version: int, manifest_path: Path, cache: Path, seed: str) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text("utf8"))
    totals = Counter()
    by_family: dict[str, Counter] = defaultdict(Counter)
    verified = 0
    for item in manifest["files"]:
        path = cache / item["family"] / Path(item["path"]).name
        data = path.read_bytes()
        if _git_blob_sha(data) != item["blob_sha"]:
            raise ValueError(f"FUNNEL_HOLDOUT_{version}_BLOB_SHA_MISMATCH:{item['path']}")
        verified += 1
        rows = _events(path)
        train, holdout = _split(rows, seed)
        hypotheses, _training, _passes = replay_training(train, config=CONFIG)
        for raw in holdout:
            baseline = parse_security_multipass(raw)
            result = run_funnel_event(raw, hypotheses, config=CONFIG)
            selected = result.selected
            assert_source_accounting(baseline)
            assert_source_accounting(selected)
            stats = by_family[item["family"]]
            totals["events"] += 1
            stats["events"] += 1
            if baseline.status == "SOURCE_PARSED":
                totals["baseline_complete"] += 1
                stats["baseline_complete"] += 1
                if (
                    baseline.vendor_fields != selected.vendor_fields
                    or baseline.value_spans != selected.value_spans
                    or baseline.issues != selected.issues
                    or baseline.unparsed != selected.unparsed
                ):
                    totals["complete_divergence"] += 1
                    stats["complete_divergence"] += 1
                continue
            totals["baseline_incomplete"] += 1
            stats["baseline_incomplete"] += 1
            before = _claims(baseline)
            after = _claims(selected)
            if baseline.raw != selected.raw:
                totals["raw_mismatch"] += 1
                stats["raw_mismatch"] += 1
                continue
            if not before <= after:
                totals["span_loss"] += 1
                stats["span_loss"] += 1
                continue
            gain = len(after - before)
            if gain:
                totals["augmented_events"] += 1
                totals["added_spans"] += gain
                stats["augmented_events"] += 1
                stats["added_spans"] += gain
                if selected.status == "SOURCE_PARSED":
                    totals["complete_promotions"] += 1
                    stats["complete_promotions"] += 1
            else:
                totals["abstentions"] += 1
                stats["abstentions"] += 1
    return {
        "version": version,
        "verified_git_blob_files": verified,
        "file_set_sha256": manifest["file_set_sha256"],
        "upstream_revision": manifest["upstream_revision"],
        "totals": dict(totals),
        "by_family": {k: dict(v) for k, v in sorted(by_family.items())},
    }


def run() -> dict[str, Any]:
    cases = [_evaluate(*case) for case in CASES]
    result = {
        "contract": "parser-studio.poc.funnel-beam-fresh-holdouts.v1",
        "product_baseline_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "funnel_core_sha256": _module_sha256("funnel_beam_poc.py"),
        "structural_hypothesis_sha256": _module_sha256("structural_hypothesis_poc.py"),
        "runtime_ranked": False,
        "evaluation_feedback_into_training": False,
        "raw_values_published": False,
        "cases": cases,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
