"""Verify Funnel/Beam PoC evidence against immutable Structural PoC references."""
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


def git_bytes(name: str) -> bytes:
    return subprocess.check_output(
        ["git", "show", f"{STRUCTURAL_COMMIT}:poc/vendor_engine/{name}"],
        cwd=REPO,
    )


def git_json(name: str) -> dict:
    return json.loads(git_bytes(name))


def main() -> None:
    broad = load("funnel-beam-security-poc-summary.json")
    reference = load("funnel-beam-reference-validation-summary.json")
    fresh = load("funnel-beam-fresh-holdouts-summary.json")
    multilayer = load("funnel-beam-multilayer-watchguard-summary.json")
    regression = load("funnel-beam-regression-summary.json")

    funnel_sha = sha256(BASE / "funnel_beam_poc.py")
    structural_sha = sha256(BASE / "structural_hypothesis_poc.py")
    for evidence in (broad, reference, fresh, multilayer, regression):
        assert evidence["funnel_core_sha256"] == funnel_sha
        assert evidence["structural_hypothesis_sha256"] == structural_sha
    assert git_bytes("structural_hypothesis_poc.py") == (
        BASE / "structural_hypothesis_poc.py"
    ).read_bytes()

    agg = broad["aggregate"]
    assert agg.get("raw_mismatch", 0) == 0
    assert agg.get("baseline_span_loss", 0) == 0
    assert agg.get("baseline_complete_divergence", 0) == 0
    assert agg.get("mutation_false_complete", 0) == 0
    assert agg["baseline_complete_exact_preserved"] == agg["baseline_source_parsed"]
    assert broad["max_pass_observed"] <= broad["max_passes"] == 6
    assert broad["beam_width"] == 4

    cisco = git_json("structural-hypothesis-cisco-reference-multisplit-summary.json")
    snort = git_json("structural-hypothesis-snort-numeric-prefix-multisplit-summary.json")
    sophos = git_json("structural-hypothesis-sophos-numeric-prefix-multisplit-summary.json")
    families = reference["families"]
    expected = {"cisco_secure_email": 44, "snort_ids_ips": 60, "sophos_utm": 54}
    old = {"cisco_secure_email": cisco, "snort_ids_ips": snort, "sophos_utm": sophos}
    for family, count in expected.items():
        assert old[family]["aggregate_metrics"]["added_spans"] == count
        assert old[family]["aggregate_metrics"]["independently_validated_spans"] == count
        assert families[family]["funnel_added_spans"] == count
        assert families[family]["range_matches"] == count
        assert families[family]["range_extras"] == 0
    assert reference["all_funnel_positive_ranges_previously_independently_validated"] is True
    assert reference["totals"] == {
        "extra_unvalidated_ranges": 0,
        "funnel_added_spans": 158,
        "matched_prior_independently_validated_ranges": 158,
        "prior_independently_validated_spans": 158,
    }

    netscout = git_json("structural-hypothesis-netscout-csv-label-multisplit-summary.json")
    symantec = git_json("structural-hypothesis-symantec-csv-label-multisplit-summary.json")
    bsd = git_json("structural-hypothesis-watchguard-extended-bsd-multisplit-summary.json")
    typed = git_json("structural-hypothesis-watchguard-typed-label-multisplit-summary.json")
    prior_dev = (
        netscout["aggregate_metrics"]["independently_validated_spans"]
        + symantec["aggregate_metrics"]["independently_validated_spans"]
        + bsd["aggregate_metrics"]["official_exact_capture_span"]
        + typed["aggregate_metrics"]["independent_exact_value"]
    )
    assert prior_dev == 2991
    assert multilayer["prospective_generalization_claim"] is False
    assert multilayer["all_added_spans_independently_validated"] is True
    assert multilayer["metrics"]["added_spans"] == 48
    assert multilayer["metrics"]["independently_validated_spans"] == 48
    assert multilayer["metrics"]["chained_events"] == 6
    assert multilayer["max_event_pass_observed"] == 3

    old_h2 = git_json("structural-hypothesis-fresh-security-holdout-2-summary.json")
    old_h3 = git_json("structural-hypothesis-fresh-security-holdout-3-summary.json")
    cases = {case["version"]: case for case in fresh["cases"]}
    assert old_h2["totals"]["baseline_incomplete"] == cases[2]["totals"]["baseline_incomplete"] == 49
    assert old_h2["totals"]["abstentions"] == cases[2]["totals"]["abstentions"] == 49
    assert old_h3["totals"]["baseline_incomplete"] == cases[3]["totals"]["baseline_incomplete"] == 1
    assert old_h3["totals"]["abstentions"] == cases[3]["totals"]["abstentions"] == 1
    assert cases[2]["totals"].get("augmented_events", 0) == 0
    assert cases[3]["totals"].get("augmented_events", 0) == 0

    assert regression["focused"] == {
        "tests": 38, "failures": 0, "errors": 0, "skips": 0
    }
    assert regression["full_vendor_engine"] == {
        "tests": 444, "failures": 0, "errors": 0, "optional_skips": 14
    }
    assert regression["broad_summary_sha256"] == sha256(BASE / "funnel-beam-security-poc-summary.json")
    assert regression["reference_summary_sha256"] == sha256(BASE / "funnel-beam-reference-validation-summary.json")
    assert regression["fresh_holdouts_summary_sha256"] == sha256(BASE / "funnel-beam-fresh-holdouts-summary.json")
    assert regression["multilayer_summary_sha256"] == sha256(BASE / "funnel-beam-multilayer-watchguard-summary.json")

    print(json.dumps({
        "status": "PASS",
        "strict_independent_reference": "158/158",
        "fresh_holdout_2_abstention": "49/49",
        "fresh_holdout_3_abstention": "1/1",
        "multilayer_watchguard": "48/48 exact; 6 chained; max pass 3",
        "broad_complete_preserved": f"{agg['baseline_complete_exact_preserved']}/{agg['baseline_source_parsed']}",
        "broad_added_spans": agg["added_spans"],
        "broad_improved_events": agg["improved_events"],
        "mutation_false_complete": agg.get("mutation_false_complete", 0),
        "full_regression": "444 tests / 14 optional skips / 0 failures / 0 errors",
        "funnel_core_sha256": funnel_sha,
        "structural_hypothesis_sha256": structural_sha,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
