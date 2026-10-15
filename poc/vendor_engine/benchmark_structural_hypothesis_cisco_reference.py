"""Independent reference check for Structural Hypothesis Cisco Secure Email promotions.

Uses the pinned Elastic integration expected JSON only for evaluation.  The
learner never receives these expected values.  Output is value-free.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmark_structural_hypothesis_security import _events, _split, LOCAL_CACHE
from multipass_adjudicator import parse_security_multipass, parse_security_once
from structural_hypothesis_poc import (
    learn_relative_rgram_hypotheses,
    merge_residual_hypothesis,
    parse_with_relative_rgram,
)

RAW = LOCAL_CACHE / "cisco_secure_email_text_mail.log"
EXPECTED = LOCAL_CACHE / "cisco_secure_email_text_mail_expected.json"
OUT = Path(__file__).resolve().parent / "structural-hypothesis-cisco-reference-summary.json"

DERIVED_PREFIXES = (
    "@timestamp",
    "ecs.",
    "tags",
    "event.kind",
    "event.original",
    "event.timezone",
    "log.level",
    "log.syslog.priority",
    "cisco_secure_email_gateway.log.category.",
)


def _flatten(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, path + (str(key),))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten(item, path + (str(index),))
        return
    yield ".".join(path), value


def _leaf_strings(doc: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for path, value in _flatten(doc):
        if path == "event.original" or any(path.startswith(prefix) for prefix in DERIVED_PREFIXES):
            continue
        if isinstance(value, bool) or value is None:
            continue
        text = str(value)
        if text:
            result[text].add(path)
    return result


def run() -> dict[str, Any]:
    rows = _events(RAW)
    expected = json.loads(EXPECTED.read_text("utf8"))["expected"]
    by_original: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in expected:
        original = doc.get("event", {}).get("original")
        if isinstance(original, str):
            by_original[original].append(doc)

    train, holdout = _split(rows)
    hypotheses = learn_relative_rgram_hypotheses(
        [parse_security_once(raw) for raw in train]
    )
    counters = Counter()
    matched_paths = Counter()
    added_slots = Counter()
    promoted_digests: list[str] = []

    reputation_slots: set[int] = set()
    for signature in hypotheses:
        variable_index = -1
        for index, token in enumerate(signature):
            if token != "<VAR>":
                continue
            variable_index += 1
            before = signature[index - 1] if index else None
            after = signature[index + 1] if index + 1 < len(signature) else None
            if before == "reputation" and after == "matched":
                reputation_slots.add(variable_index)

    for raw in holdout:
        baseline = parse_security_multipass(raw)
        if baseline.status == "SOURCE_PARSED":
            continue
        structural_view = parse_security_once(raw)
        candidate = parse_with_relative_rgram(raw, structural_view, hypotheses)
        merged = merge_residual_hypothesis(baseline, candidate)
        if merged is None:
            continue
        counters["promoted_events"] += 1
        promoted_digests.append(hashlib.sha256(raw.encode("utf8")).hexdigest())

        docs = by_original.get(raw, [])
        if not docs:
            counters["promoted_events_without_expected_doc"] += 1
            continue
        # If duplicate originals exist, any official expected document may
        # validate the exact source occurrence.
        leaf_maps = [_leaf_strings(doc) for doc in docs]
        baseline_span_ranges = {
            (span.start_byte, span.end_byte) for span in baseline.value_spans
        }
        additions = [
            span for span in candidate.value_spans
            if (span.start_byte, span.end_byte) not in baseline_span_ranges
        ]
        counters["added_spans"] += len(additions)
        raw_bytes = raw.encode("utf8")
        for span in additions:
            value = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
            slot_match = __import__("re").search(r"slot_(\d+)$", span.path)
            slot = int(slot_match.group(1)) if slot_match else -1
            added_slots[f"slot_{slot}"] += 1
            paths: set[str] = set()
            for leaf_map in leaf_maps:
                paths.update(leaf_map.get(value, set()))
            if paths:
                counters["added_spans_exact_expected_value"] += 1
                for path in paths:
                    matched_paths[path] += 1
            elif slot in reputation_slots:
                counters["added_spans_vendor_documented_reputation_value"] += 1
            else:
                counters["added_spans_unvalidated"] += 1

    result = {
        "contract": "parser-studio.poc.structural-hypothesis-cisco-reference.v1",
        "scope": "CISCO_SECURE_EMAIL_PROMOTIONS_ONLY",
        "learner_expected_values_used": False,
        "expected_reference_source": "elastic/integrations",
        "expected_reference_revision": "57ac255efb40d98151337b4ff11b9015679391ed",
        "expected_reference_file_blob_sha": "64a877228883a14e230eddd290d7116947b1da2c",
        "pipeline_reference_file_blob_sha": "193201b0e80f155a0854db6a81f20473148d777a",
        "raw_values_published": False,
        "raw_events": len(rows),
        "train_events": len(train),
        "holdout_events": len(holdout),
        "hypothesis_count": len(hypotheses),
        "metrics": dict(counters),
        "promotion_event_sha256": sorted(promoted_digests),
        "added_slot_counts": dict(sorted(added_slots.items())),
        "matched_expected_paths": dict(sorted(matched_paths.items())),
        "vendor_documented_reputation_slot_indexes": sorted(reputation_slots),
        "vendor_document_reference": {
            "title": "Enable URL Logging on Email Security Appliance (ESA)",
            "publisher": "Cisco",
            "document_id": "226298",
            "verified_log_shape": "MID <value> URL <value> has reputation <value> matched Condition: URL Reputation Rule",
        },
        "interpretation": (
            "Evaluation-only references validate added source values without "
            "feeding semantics to the learner: Elastic expected JSON validates "
            "mapped values, and Cisco's vendor documentation validates the "
            "reputation-score slot that Elastic does not map."
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf8")
    return result


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
