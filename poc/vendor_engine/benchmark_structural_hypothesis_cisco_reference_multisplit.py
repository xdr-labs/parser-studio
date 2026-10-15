"""Independent multi-split reference validation for Cisco Secure Email promotions."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmark_structural_hypothesis_multisplit import SEEDS, _split_seed
from benchmark_structural_hypothesis_security import _events, LOCAL_CACHE
from multipass_adjudicator import parse_security_multipass, parse_security_once
from structural_hypothesis_poc import (
    learn_relative_rgram_hypotheses,
    merge_residual_hypothesis,
    parse_with_relative_rgram,
)

RAW = LOCAL_CACHE / "cisco_secure_email_text_mail.log"
EXPECTED = LOCAL_CACHE / "cisco_secure_email_text_mail_expected.json"
OUT = Path(__file__).resolve().parent / "structural-hypothesis-cisco-reference-multisplit-summary.json"

DERIVED_PREFIXES = (
    "@timestamp", "ecs.", "tags", "event.kind", "event.original",
    "event.timezone", "log.level", "log.syslog.priority",
    "cisco_secure_email_gateway.log.category.",
)


def _flatten(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, path + (str(key),))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten(item, path + (str(index),))
    else:
        yield ".".join(path), value


def _leaf_map(doc: dict[str, Any]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for path, value in _flatten(doc):
        if path == "event.original" or any(path.startswith(p) for p in DERIVED_PREFIXES):
            continue
        if value is None or isinstance(value, bool):
            continue
        text = str(value)
        if text:
            out[text].add(path)
    return out


def _vendor_documented_slots(hypotheses) -> tuple[set[int], set[int]]:
    reputation: set[int] = set()
    url: set[int] = set()
    for signature in hypotheses:
        variable_index = -1
        for index, token in enumerate(signature):
            if token != "<VAR>":
                continue
            variable_index += 1
            before = signature[index - 1] if index else None
            after = signature[index + 1] if index + 1 < len(signature) else None
            if before == "reputation" and after == "matched":
                reputation.add(variable_index)
            if before == "URL" and after == "has":
                url.add(variable_index)
    return reputation, url


def _evaluate(seed: str, rows: list[str], by_original) -> dict[str, Any]:
    train, holdout = _split_seed(rows, seed)
    hypotheses = learn_relative_rgram_hypotheses(
        [parse_security_once(raw) for raw in train]
    )
    reputation_slots, url_slots = _vendor_documented_slots(hypotheses)
    metrics = Counter()
    paths = Counter()
    promoted = []

    for raw in holdout:
        baseline = parse_security_multipass(raw)
        if baseline.status == "SOURCE_PARSED":
            continue
        candidate = parse_with_relative_rgram(
            raw, parse_security_once(raw), hypotheses
        )
        merged = merge_residual_hypothesis(baseline, candidate)
        if merged is None:
            continue
        metrics["promoted_events"] += 1
        promoted.append(hashlib.sha256(raw.encode("utf8")).hexdigest())
        docs = by_original.get(raw, [])
        if not docs:
            metrics["events_without_expected_doc"] += 1
            continue
        leaves = [_leaf_map(doc) for doc in docs]
        baseline_ranges = {
            (s.start_byte, s.end_byte) for s in baseline.value_spans
        }
        additions = [
            s for s in candidate.value_spans
            if (s.start_byte, s.end_byte) not in baseline_ranges
        ]
        raw_bytes = raw.encode("utf8")
        metrics["added_spans"] += len(additions)
        for span in additions:
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            matched = set()
            for leaf in leaves:
                matched.update(leaf.get(value, set()))
            if matched:
                metrics["elastic_expected_exact"] += 1
                for path in matched:
                    paths[path] += 1
                continue
            import re
            m = re.search(r"slot_(\d+)$", span.path)
            slot = int(m.group(1)) if m else -1
            if slot in reputation_slots:
                metrics["cisco_documented_reputation"] += 1
            elif slot in url_slots:
                metrics["cisco_documented_url"] += 1
            else:
                metrics["unvalidated"] += 1

    metrics["independently_validated_spans"] = (
        metrics["elastic_expected_exact"]
        + metrics["cisco_documented_reputation"]
        + metrics["cisco_documented_url"]
    )
    return {
        "seed": seed,
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_count": len(hypotheses),
        "metrics": dict(metrics),
        "matched_expected_paths": dict(sorted(paths.items())),
        "promotion_event_sha256": sorted(promoted),
    }


def run() -> dict[str, Any]:
    rows = _events(RAW)
    expected = json.loads(EXPECTED.read_text("utf8"))["expected"]
    by_original: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in expected:
        original = doc.get("event", {}).get("original")
        if isinstance(original, str):
            by_original[original].append(doc)

    splits = [_evaluate(seed, rows, by_original) for seed in SEEDS]
    aggregate = Counter()
    unique_promotions = set()
    for split in splits:
        aggregate.update(split["metrics"])
        unique_promotions.update(split["promotion_event_sha256"])

    result = {
        "contract": "parser-studio.poc.structural-hypothesis-cisco-reference-multisplit.v1",
        "scope": "CISCO_SECURE_EMAIL_PROMOTIONS_ONLY",
        "split_count": len(splits),
        "learner_reference_values_used": False,
        "raw_values_published": False,
        "elastic_expected_reference_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "elastic_expected_blob_sha": "64a877228883a14e230eddd290d7116947b1da2c",
        "elastic_pipeline_blob_sha": "193201b0e80f155a0854db6a81f20473148d777a",
        "cisco_vendor_document_id": "226298",
        "splits": splits,
        "aggregate_metrics": dict(aggregate),
        "unique_promoted_events": len(unique_promotions),
        "all_added_spans_independently_validated": (
            aggregate["added_spans"] > 0
            and aggregate["added_spans"] == aggregate["independently_validated_spans"]
            and aggregate["unvalidated"] == 0
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
