#!/usr/bin/env python3
"""ACC-2 independent partial non-JSON publisher assertions, digest-only.

Publisher goldens are PARTIAL: score recalled exact source span/value claims
ONLY. Do not calculate F1, false-positive rates, or vendor semantic accuracy.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "multipass"))

from accuracy_shadow import choose_shadow
from bounded_funnel import FunnelConfig, run_funnel_batch, run_funnel_event
from multipass_contract import CandidateEvidence, candidate_from_event
from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch
from multipass_preview_api import preview_batch

PINNED_ORACLE_SHA256 = "18c25739376c4bd7289066e147ac73fc5e55344385b0312e7c0e6cab00cea17b"
EVIDENCE = CandidateEvidence(
    "acc2-publisher-assertions", None, None,
    "HEURISTIC_RESIDUAL", False, "20261022-partial-source",
)


def validate_oracle(golden_file: Path, summary_file: Path, sources_file: Path) -> tuple:
    bytes_in = golden_file.read_bytes()
    if sha256(bytes_in).hexdigest() != PINNED_ORACLE_SHA256:
        raise ValueError("PUBLISHER_FIELD_ORACLE_CHANGED")
    summary = json.loads(summary_file.read_bytes())
    if summary.get("qualified_oracle_v2_sha256") != PINNED_ORACLE_SHA256:
        raise ValueError("PUBLISHER_ORACLE_SUMMARY_CHANGED")
    if summary.get("upstream_sources_sha256") != sha256(sources_file.read_bytes()).hexdigest():
        raise ValueError("PUBLISHER_SOURCES_PIN_CHANGED")
    if summary.get("source_only_not_native_certification") is not True:
        raise ValueError("PUBLISHER_SOURCE_SCOPE_INVALID")
    rows = json.loads(bytes_in.decode("utf8"))
    if len(rows) != summary["original_events"]:
        raise ValueError("PUBLISHER_RECORD_COUNT_CHANGED")
    status = Counter(row["status"] for row in rows)
    if dict(status) != summary["status_counts"]:
        raise ValueError("PUBLISHER_ORACLE_STATUS_CHANGED")
    expected_assertions = 0
    for row in rows:
        if row["status"] != "SCORABLE_SOURCE_ONLY" and row.get("raw") is None:
            # One upstream assertion has no original record. It is excluded
            # from all positive/negative accuracy denominators.
            continue
        if not isinstance(row.get("raw"), str):
            raise ValueError("PUBLISHER_SCORABLE_SOURCE_MISSING")
        raw = row["raw"].encode("utf8")
        if sha256(raw).hexdigest() != row["raw_sha256"] or len(raw) != row["raw_bytes"]:
            raise ValueError("PUBLISHER_ORIGINAL_EVENT_TAMPERED")
        if len(raw) > 65536:
            raise ValueError("PUBLISHER_EVENT_TOO_LARGE")
        if row["status"] == "SCORABLE_SOURCE_ONLY":
            expected_assertions += len(row["fields"])
            for claim in row["fields"]:
                a = claim["start_byte"]
                b = claim["end_byte"]
                if not 0 <= a <= b <= len(raw):
                    raise ValueError("PUBLISHER_GOLDEN_SPAN_INVALID")
                try:
                    lexeme = raw[a:b].decode("utf8", "strict")
                    raw[:a].decode("utf8", "strict")
                    raw[:b].decode("utf8", "strict")
                except UnicodeDecodeError as exc:
                    raise ValueError("PUBLISHER_GOLDEN_UTF8_INVALID") from exc
                if lexeme != str(claim["value"]):
                    raise ValueError("PUBLISHER_GOLDEN_SPAN_VALUE_MISMATCH")
    if expected_assertions != summary["source_triples"]:
        raise ValueError("PUBLISHER_GOLDEN_CLAIMS_CHANGED")
    return rows, summary


def _published_claims(row: dict) -> Counter:
    return Counter(
        (field["start_byte"], field["end_byte"], str(field["value"]))
        for field in row["fields"]
    )


def _extracted_claims(candidate: object) -> Counter:
    return Counter(
        (value.start_byte, value.end_byte, str(value.value))
        for value in candidate.occurrences
    )


def score_partial_publisher(golden_file: Path, summary_file: Path, sources_file: Path) -> dict:
    rows, summary = validate_oracle(golden_file, summary_file, sources_file)
    results = defaultdict(Counter)
    product_status = defaultdict(Counter)
    pool_sizes = Counter()
    shadow_changes = 0
    candidates_rejected = 0
    product_with_missing_assertion_while_complete = 0
    shadow_with_missing_assertion_while_complete = 0

    for row in rows:
        if row["status"] != "SCORABLE_SOURCE_ONLY":
            continue
        raw = row["raw"]
        batch = parse_security_batch(
            raw, parser=parse_security_multipass,
            max_bytes=65536, max_events=500,
        )
        if len(batch.frames) != 1:
            raise ValueError("SCORABLE_EVENT_FRAMING_MISMATCH")
        frame = batch.frames[0]
        preview = preview_batch(raw)
        if preview["eventCount"] != 1:
            raise ValueError("PUBLISHER_PREVIEW_MULTIEVENT")
        funnel = run_funnel_batch([frame.raw])
        protected = any(
            issue.startswith(("FRAMING_", "SCHEMA_"))
            for issue in frame.event.issues
        )
        accepted_event = frame.event if protected else funnel.selected[0]
        observed = preview["events"][0]["preview"]
        if (
            observed["status"] != accepted_event.status
            or observed["issues"] != accepted_event.issues
            or len(observed["spans"]) != len(accepted_event.value_spans)
        ):
            raise ValueError("PUBLISHER_PRODUCT_PREVIEW_MISMATCH")
        product = candidate_from_event(accepted_event, EVIDENCE)
        base = candidate_from_event(frame.event, EVIDENCE)
        exploratory = run_funnel_event(
            frame.raw, funnel.hypotheses, config=FunnelConfig(beam_width=4)
        )
        pool = [product]
        for item in [base, *(
            candidate_from_event(state.event, EVIDENCE)
            for state in exploratory.beam
        )]:
            if all(
                (item.completeness, item.occurrences, item.issues)
                != (old.completeness, old.occurrences, old.issues)
                for old in pool
            ):
                pool.append(item)
        decision = choose_shadow(frame.raw, pool, base)
        if decision.selected_index is None:
            raise ValueError("PUBLISHER_NO_VALID_SHADOW")
        choice = pool[decision.selected_index]
        if protected and choice.completeness == "SOURCE_PARSED":
            raise ValueError("PUBLISHER_PROTECTED_STATUS_PROMOTED")
        pool_sizes[len(pool)] += 1
        candidates_rejected += sum(not score.valid for score in decision.scores)
        if choice.occurrences != product.occurrences:
            shadow_changes += 1
        expected = _published_claims(row)
        found_product = _extracted_claims(product)
        found_shadow = _extracted_claims(choice)
        exact_product = sum((expected & found_product).values())
        exact_shadow = sum((expected & found_shadow).values())
        counts = results[row["family"]]
        counts["events"] += 1
        counts["assertions"] += sum(expected.values())
        counts["product_exact"] += exact_product
        counts["shadow_exact"] += exact_shadow
        counts["product_missed"] += sum((expected - found_product).values())
        counts["shadow_missed"] += sum((expected - found_shadow).values())
        product_status[row["family"]][product.completeness] += 1
        if product.completeness == "SOURCE_PARSED" and exact_product < sum(expected.values()):
            product_with_missing_assertion_while_complete += 1
        if choice.completeness == "SOURCE_PARSED" and exact_shadow < sum(expected.values()):
            shadow_with_missing_assertion_while_complete += 1

    return {
        "contract": "parser-studio.acc2.publisher-nonjson-source-claims.v0.1",
        "provenance": "PINNED_UPSTREAM_AUTHORED_SOURCE_ASSERTIONS_PARTIAL_TRUTH",
        "oracle_sha256": PINNED_ORACLE_SHA256,
        "source_manifest_sha256": sha256(sources_file.read_bytes()).hexdigest(),
        "total_originals": len(rows),
        "scorable_originals": summary["scorable_originals"],
        "scored_publisher_assertions": summary["source_triples"],
        "excluded_statuses": {
            k: v for k, v in sorted(Counter(row["status"] for row in rows).items())
            if k != "SCORABLE_SOURCE_ONLY"
        },
        "per_family": {
            family: {
                **dict(sorted(counts.items())),
                "product_status_counts": dict(sorted(product_status[family].items())),
            }
            for family, counts in sorted(results.items())
        },
        "pool_sizes": {str(n): count for n, count in sorted(pool_sizes.items())},
        "shadow_rejected_candidates": candidates_rejected,
        "shadow_changed_field_claims": shadow_changes,
        "product_complete_but_missing_publisher_triples": product_with_missing_assertion_while_complete,
        "shadow_complete_but_missing_publisher_triples": shadow_with_missing_assertion_while_complete,
        "field_precision_f1": "NOT_SCORABLE_WITH_INCOMPLETE_UPSTREAM_FIELDS",
        "field_roles_stellar_7_0": "NOT_SCORED",
        "native_target_and_wire": "NOT_VERIFIED",
        "raw_values_emitted": False,
        "product_runtime_modified": False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Digest-only partial publisher source-claim scoring")
    p.add_argument("--oracle", type=Path, required=True)
    p.add_argument("--summary", type=Path, required=True)
    p.add_argument("--sources", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = score_partial_publisher(args.oracle, args.summary, args.sources)
    report = json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
