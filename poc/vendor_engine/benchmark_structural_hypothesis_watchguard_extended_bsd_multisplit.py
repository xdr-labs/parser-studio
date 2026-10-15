"""Development-only WatchGuard extended-BSD envelope validation.

The candidate was designed after the first fresh holdout became development
data.  Validation compares candidate source spans to the pinned Elastic
WatchGuard default pipeline's grok capture boundaries, not to learner inputs.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from benchmark_structural_hypothesis_multisplit import SEEDS
from multipass_adjudicator import parse_security_multipass
from structural_hypothesis_poc import (
    augment_partial_with_extended_bsd_envelope,
    learn_extended_bsd_envelope_hypotheses,
    parse_extended_bsd_envelope,
)

BASE = Path(__file__).resolve().parent
CACHE = BASE / ".cache" / "structural_hypothesis_fresh_holdout"
MANIFEST = BASE / "STRUCTURAL_HYPOTHESIS_FRESH_SECURITY_HOLDOUT_20261015.json"
OUT = BASE / "structural-hypothesis-watchguard-extended-bsd-multisplit-summary.json"

WATCH_HOST = r"(?:[0-9A-Za-z][0-9A-Za-z\-_]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z\-_]{0,62}))*(?:\.?|\b)"
OFFICIAL = re.compile(
    r"^<(?P<priority>\d+)>"
    r"(?P<syslog_timestamp>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>" + WATCH_HOST + r")"
    r"(?: (?P<serial_number>[A-Za-z0-9_]+))?"
    r"(?: (?P<member_info>" + WATCH_HOST + r"))?"
    r"(?: \((?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\))? "
    r"(?P<appname>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?:\[(?P<procid>\d+)\])?: "
    r"(?P<body>.*)$"
)
CAPTURES = (
    "priority", "syslog_timestamp", "hostname", "serial_number",
    "member_info", "timestamp", "appname", "procid",
)
PIPELINE_SHA = "4c64981d839ccbbf403490fc6ab646cfbebdf604"


def _all_rows():
    manifest = json.loads(MANIFEST.read_text("utf8"))
    rows = []
    for item in manifest["files"]:
        path = CACHE / item["family"] / Path(item["path"]).name
        for raw in path.read_text("utf8").splitlines():
            if raw.strip():
                rows.append((item["family"], raw))
    return rows


def _split(rows, seed):
    ordered = sorted(
        rows,
        key=lambda item: hashlib.sha256(
            (seed + "|" + item[1]).encode("utf8")
        ).hexdigest(),
    )
    count = max(3, min(len(ordered)-1, round(len(ordered)*0.65)))
    return ordered[:count], ordered[count:]


def _official_ranges(raw: str):
    match = OFFICIAL.match(raw)
    if match is None:
        return None
    result = set()
    for name in CAPTURES:
        if match.group(name) is None:
            continue
        a, b = match.span(name)
        result.add((
            len(raw[:a].encode("utf8")),
            len(raw[:b].encode("utf8")),
        ))
    return result


def run_seed(seed, rows):
    train, holdout = _split(rows, seed)
    hypotheses = learn_extended_bsd_envelope_hypotheses(
        [raw for _family, raw in train]
    )
    metrics = Counter()
    by_family = defaultdict(Counter)

    for family, raw in holdout:
        baseline = parse_security_multipass(raw)
        candidate = parse_extended_bsd_envelope(raw, hypotheses)
        augmented = augment_partial_with_extended_bsd_envelope(
            baseline, candidate
        )
        if augmented is None or candidate is None:
            continue

        metrics["augmented_events"] += 1
        by_family[family]["augmented_events"] += 1
        metrics["still_incomplete"] += int(augmented.status != "SOURCE_PARSED")
        metrics["unexpected_complete"] += int(augmented.status == "SOURCE_PARSED")

        base_keys = {
            (s.path, s.source_segments, s.start_byte, s.end_byte)
            for s in baseline.value_spans
        }
        aug_keys = {
            (s.path, s.source_segments, s.start_byte, s.end_byte)
            for s in augmented.value_spans
        }
        metrics["baseline_span_preserved"] += int(base_keys <= aug_keys)
        metrics["baseline_span_loss"] += int(not base_keys <= aug_keys)

        official = _official_ranges(raw)
        if official is not None:
            metrics["events_matching_official_grok"] += 1
        base_ranges = {(s.start_byte, s.end_byte) for s in baseline.value_spans}
        for span in augmented.value_spans:
            key = (span.start_byte, span.end_byte)
            if key in base_ranges:
                continue
            metrics["added_spans"] += 1
            by_family[family]["added_spans"] += 1
            if official is not None and key in official:
                metrics["official_exact_capture_span"] += 1
                by_family[family]["official_exact_capture_span"] += 1
            else:
                metrics["unvalidated_spans"] += 1
                by_family[family]["unvalidated_spans"] += 1

        mutations = [
            raw[:len(raw)//2] + "\x00" + raw[len(raw)//2:],
            raw.replace("(", "[", 1) if "(" in raw else raw,
        ]
        for mutated in mutations:
            if mutated == raw:
                continue
            metrics["mutation_attempts"] += 1
            mutated_base = parse_security_multipass(mutated)
            mutated_candidate = parse_extended_bsd_envelope(
                mutated, hypotheses
            )
            mutated_aug = augment_partial_with_extended_bsd_envelope(
                mutated_base, mutated_candidate
            )
            if mutated_aug is not None:
                metrics["mutation_augmentation"] += 1
                if mutated_aug.status == "SOURCE_PARSED":
                    metrics["mutation_false_complete"] += 1

    return {
        "seed": seed,
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_shapes": {
            str(shape): hypothesis.training_support
            for shape, hypothesis in sorted(hypotheses.items())
        },
        "metrics": dict(metrics),
        "by_family": {k: dict(v) for k, v in sorted(by_family.items())},
    }


def run():
    rows = _all_rows()
    splits = [run_seed(seed, rows) for seed in SEEDS]
    aggregate = Counter()
    by_family = defaultdict(Counter)
    for split in splits:
        aggregate.update(split["metrics"])
        for family, values in split["by_family"].items():
            by_family[family].update(values)
    result = {
        "contract": "parser-studio.poc.extended-bsd-envelope-development.v1",
        "scope": "FIRST_FRESH_HOLDOUT_DEVELOPMENT_ONLY",
        "prospective_claim_allowed": False,
        "learner_vendor_identity_used": False,
        "learner_reference_values_used": False,
        "raw_values_published": False,
        "elastic_watchguard_default_pipeline_sha": PIPELINE_SHA,
        "official_grok_shape": (
            "PRI + SYSLOGTIMESTAMP + WATCHGUARDHOSTNAME + optional WORD/"
            "member + optional ISO8601 + PROG + optional procid"
        ),
        "aggregate_metrics": dict(aggregate),
        "aggregate_by_family": {
            k: dict(v) for k, v in sorted(by_family.items())
        },
        "all_added_spans_independently_validated": (
            aggregate["added_spans"] > 0
            and aggregate["added_spans"] == aggregate["official_exact_capture_span"]
            and aggregate["unvalidated_spans"] == 0
        ),
        "all_mutations_fail_closed": (
            aggregate["mutation_attempts"] > 0
            and aggregate["mutation_augmentation"] == 0
            and aggregate["mutation_false_complete"] == 0
        ),
        "splits": splits,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
