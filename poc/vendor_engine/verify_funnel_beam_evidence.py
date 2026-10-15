"""Verify Funnel/Beam PoC evidence and immutable Structural PoC lineage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[1]
STRUCTURAL_COMMIT = "57be1b9872b5dc9ba516b58fa7c1c976bbebd0d4"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name: str) -> dict:
    return json.loads((BASE / name).read_text("utf8"))


def git_bytes(path: str) -> bytes:
    return subprocess.check_output(
        ["git", "show", f"{STRUCTURAL_COMMIT}:poc/vendor_engine/{path}"],
        cwd=REPO,
    )


def main() -> None:
    broad = load("funnel-beam-security-poc-summary.json")
    reference = load("funnel-beam-reference-validation-summary.json")
    fresh = load("funnel-beam-fresh-holdouts-summary.json")
    multilayer = load("funnel-beam-multilayer-watchguard-summary.json")
    ablation = load("funnel-beam-ablation-summary.json")
    regression = load("funnel-beam-regression-summary.json")

    funnel_sha = sha256(BASE / "funnel_beam_poc.py")
    structural_sha = sha256(BASE / "structural_hypothesis_poc.py")
    assert funnel_sha == "85d90ba07f13544fb337007699ca3b143315bd8434df3a0a4a490b4e3e9098ff"
    assert structural_sha == "1acd829d41176a696afc2ce7561f5c6af397c75eb15e22d67b6073008d501ec5"
    assert git_bytes("structural_hypothesis_poc.py") == (
        BASE / "structural_hypothesis_poc.py"
    ).read_bytes()

    for summary in (broad, reference, multilayer, regression):
        assert summary["funnel_core_sha256"] == funnel_sha
        assert summary["structural_hypothesis_sha256"] == structural_sha

    agg = broad["aggregate"]
    assert agg.get("raw_mismatch", 0) == 0
    assert agg.get("baseline_span_loss", 0) == 0
    assert agg.get("baseline_complete_divergence", 0) == 0
    assert agg.get("mutation_false_complete", 0) == 0
    assert agg["baseline_complete_exact_preserved"] == agg["baseline_source_parsed"] == 2167
    assert agg["improved_events"] == 855
    assert agg["added_spans"] == 5844
    assert broad["max_pass_observed"] == 3
    assert broad["max_pass_observed"] <= broad["max_passes"] == 6
    assert broad["beam_width"] == 4

    assert reference["all_funnel_positive_ranges_previously_independently_validated"]
    rt = reference["totals"]
    assert rt["funnel_added_spans"] == 158
    assert rt["matched_prior_independently_validated_ranges"] == 158
    assert rt["prior_independently_validated_spans"] == 158
    assert rt["extra_unvalidated_ranges"] == 0
    assert reference["families"]["cisco_secure_email"]["range_matches"] == 44
    assert reference["families"]["snort_ids_ips"]["range_matches"] == 60
    assert reference["families"]["sophos_utm"]["range_matches"] == 54

    fresh_by_version = {case["version"]: case for case in fresh["cases"]}
    assert fresh_by_version[2]["verified_git_blob_files"] == 14
    assert fresh_by_version[2]["totals"]["baseline_incomplete"] == 49
    assert fresh_by_version[2]["totals"]["abstentions"] == 49
    assert fresh_by_version[2]["totals"].get("augmented_events", 0) == 0
    assert fresh_by_version[3]["verified_git_blob_files"] == 20
    assert fresh_by_version[3]["totals"]["baseline_incomplete"] == 1
    assert fresh_by_version[3]["totals"]["abstentions"] == 1
    assert fresh_by_version[3]["totals"].get("augmented_events", 0) == 0

    assert multilayer["all_added_spans_independently_validated"]
    mm = multilayer["metrics"]
    assert mm["added_spans"] == mm["independently_validated_spans"] == 48
    assert mm.get("unvalidated_spans", 0) == 0
    assert multilayer["chain_counts"]["partial:extended-bsd>partial:typed-label"] == 6
    assert multilayer["max_event_pass_observed"] == 3

    delta = ablation["deltas"]
    assert delta["multi_pass_gain_over_one_pass_greedy"]["added_spans"] == 50
    assert delta["beam4_gain_over_beam1_at_one_pass"]["added_spans"] == 0
    assert delta["full_gain_over_multi_pass_greedy"]["added_spans"] == 0
    for item in ablation["results"].values():
        totals = item["totals"]
        assert totals.get("raw_mismatch", 0) == 0
        assert totals.get("span_loss", 0) == 0
        assert totals.get("complete_divergence", 0) == 0

    assert regression["focused"] == {
        "tests": 38, "failures": 0, "errors": 0, "skips": 0
    }
    assert regression["full_vendor_engine"] == {
        "tests": 444, "failures": 0, "errors": 0, "optional_skips": 13
    }
    assert regression["broad_summary_sha256"] == sha256(
        BASE / "funnel-beam-security-poc-summary.json"
    )
    assert regression["reference_summary_sha256"] == sha256(
        BASE / "funnel-beam-reference-validation-summary.json"
    )
    assert regression["fresh_holdouts_summary_sha256"] == sha256(
        BASE / "funnel-beam-fresh-holdouts-summary.json"
    )
    assert regression["multilayer_summary_sha256"] == sha256(
        BASE / "funnel-beam-multilayer-watchguard-summary.json"
    )
    assert regression["ablation_summary_sha256"] == sha256(
        BASE / "funnel-beam-ablation-summary.json"
    )

    print(json.dumps({
        "status": "PASS",
        "strict_independent_reference": "158/158",
        "fresh_holdout_2_abstention": "49/49",
        "fresh_holdout_3_abstention": "1/1",
        "multilayer_independent_reference": "48/48",
        "multi_pass_added_span_gain_over_one_pass": 50,
        "beam4_added_span_gain_over_beam1": 0,
        "broad_complete_preserved": "2167/2167",
        "broad_added_span_occurrences": 5844,
        "mutation_false_complete": 0,
        "max_pass_observed": 3,
        "full_regression": "444 PASS / 13 optional skips",
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
