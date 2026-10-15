"""Reproduce a real two-layer Funnel chain on WatchGuard diagnostic logs.

This is development-only evidence. Raw values remain in ignored caches and are
never serialized. Added source spans are validated against the pinned WatchGuard
envelope grammar or pinned official expected output.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from funnel_beam_poc import FunnelConfig, replay_training, run_funnel_event
from multipass_adjudicator import parse_security_multipass

BASE = Path(__file__).resolve().parent
CACHE = BASE / ".cache" / "structural_hypothesis_fresh_holdout" / "watchguard_firebox"
RAW = CACHE / "test-diagnostic.log"
EXPECTED = CACHE / "test-diagnostic.log-expected.json"
OUT = BASE / "funnel-beam-multilayer-watchguard-summary.json"
SEED = "cascade-test-diagnostic.log"
CONFIG = FunnelConfig(max_passes=6, beam_width=4)

WATCH_HOST = (
    r"(?:[0-9A-Za-z][0-9A-Za-z\-_]{0,62})"
    r"(?:\.(?:[0-9A-Za-z][0-9A-Za-z\-_]{0,62}))*(?:\.?|\b)"
)
OFFICIAL = re.compile(
    r"^<(?P<priority>\d+)>"
    r"(?P<syslog_timestamp>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>" + WATCH_HOST + r")"
    r"(?: (?P<serial_number>[A-Za-z0-9_]+))?"
    r"(?: (?P<member_info>" + WATCH_HOST + r"))?"
    r"(?: \((?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\))? "
    r"(?P<appname>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?:\[(?P<procid>\d+)\])?: (?P<body>.*)$"
)
CAPTURES = (
    "priority", "syslog_timestamp", "hostname", "serial_number",
    "member_info", "timestamp", "appname", "procid",
)


def _module_sha256(name: str) -> str:
    return hashlib.sha256((BASE / name).read_bytes()).hexdigest()


def _events(path: Path) -> list[str]:
    return [line for line in path.read_text("utf8").splitlines() if line.strip()]


def _split(rows: list[str]) -> tuple[list[str], list[str]]:
    ordered = sorted(
        rows,
        key=lambda raw: hashlib.sha256((SEED + "|" + raw).encode("utf8")).hexdigest(),
    )
    count = max(3, min(len(ordered) - 1, round(len(ordered) * 0.65)))
    return ordered[:count], ordered[count:]


def _official_ranges(raw: str) -> set[tuple[int, int]]:
    match = OFFICIAL.match(raw)
    if match is None:
        return set()
    result = set()
    for name in CAPTURES:
        if match.group(name) is None:
            continue
        a, b = match.span(name)
        result.add((len(raw[:a].encode("utf8")), len(raw[:b].encode("utf8"))))
    return result


def _leaf_values(node) -> set[str]:
    values: set[str] = set()

    def walk(value, path=()):
        if isinstance(value, dict):
            for key, child in value.items():
                if path == () and key in {"message", "tags", "ecs"}:
                    continue
                if path == ("event",) and key == "original":
                    continue
                walk(child, path + (key,))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, path + (index,))
        elif value is not None and not isinstance(value, bool):
            values.add(str(value))

    walk(node)
    return values


def _expected_by_raw() -> dict[str, set[str]]:
    result = {}
    for doc in json.loads(EXPECTED.read_text("utf8"))["expected"]:
        raw = doc.get("event", {}).get("original")
        if isinstance(raw, str):
            result[raw] = _leaf_values(doc)
    return result


def run() -> dict:
    rows = _events(RAW)
    train, holdout = _split(rows)
    hypotheses, _training, replay_passes = replay_training(train, config=CONFIG)
    one_pass_config = FunnelConfig(max_passes=1, beam_width=4)
    one_pass_hypotheses, _one_training, one_replay_passes = replay_training(
        train, config=one_pass_config
    )
    expected = _expected_by_raw()
    metrics = Counter()
    chain_counts = Counter()
    max_pass = 0
    total_multi_added = 0
    total_one_added = 0

    for raw in holdout:
        baseline = parse_security_multipass(raw)
        result = run_funnel_event(raw, hypotheses, config=CONFIG)
        selected = result.selected
        chain = result.beam[0].provenance[1:]
        max_pass = max(max_pass, result.passes_run)
        if len(chain) < 2:
            continue
        chain_counts[">".join(chain)] += 1
        metrics["chained_events"] += 1

        baseline_ranges = {(s.start_byte, s.end_byte) for s in baseline.value_spans}
        official_ranges = _official_ranges(raw)
        expected_values = expected.get(raw, set())
        raw_bytes = raw.encode("utf8")
        for span in selected.value_spans:
            region = (span.start_byte, span.end_byte)
            if region in baseline_ranges:
                continue
            metrics["added_spans"] += 1
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            if region in official_ranges:
                metrics["official_envelope_exact"] += 1
            elif value in expected_values:
                metrics["official_expected_value_exact"] += 1
            else:
                metrics["unvalidated_spans"] += 1

    metrics["independently_validated_spans"] = (
        metrics["official_envelope_exact"] + metrics["official_expected_value_exact"]
    )
    result = {
        "contract": "parser-studio.poc.funnel-beam-watchguard-multilayer.v1",
        "scope": "DEVELOPMENT_ONLY_WATCHGUARD_DIAGNOSTIC",
        "prospective_generalization_claim": False,
        "product_baseline_head": "4596f4629a4cb7b900eb459cadffb0d2813c7957",
        "funnel_core_sha256": _module_sha256("funnel_beam_poc.py"),
        "structural_hypothesis_sha256": _module_sha256("structural_hypothesis_poc.py"),
        "training_events": len(train),
        "holdout_events": len(holdout),
        "training_replay_passes": replay_passes,
        "max_event_pass_observed": max_pass,
        "chain_counts": dict(sorted(chain_counts.items())),
        "metrics": dict(metrics),
        "all_added_spans_independently_validated": (
            metrics["added_spans"] > 0
            and metrics["added_spans"] == metrics["independently_validated_spans"]
            and metrics["unvalidated_spans"] == 0
        ),
        "raw_values_published": False,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
