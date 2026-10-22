#!/usr/bin/env python3
"""Digest-only independent publisher W3C field-span research (ACC-2).

This compares real product Preview selection and a fixed offline shadow pool.
It does NOT declare a complete field oracle or manufacturer-level F1.
Source and pinned publisher annotations must be supplied locally, never checked in.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "multipass"))

from accuracy_shadow import choose_shadow
from bounded_funnel import FunnelConfig, run_funnel_batch, run_funnel_event
from multipass_contract import CandidateEvidence, CandidateResult, candidate_from_event
from multipass_adjudicator import parse_security_multipass
from multipass_preview_api import preview_batch
from security_framing import parse_security_batch

PUBLISHER_PIN_SHA256 = "76b37af28dee2538121801320269b6152ff8199a169f458021d6d5762a5d64e5"
EVIDENCE = CandidateEvidence(
    parser_id="w3c-shadow-observation",
    profile_id="field-accuracy-shadow",
    grammar_id=None,
    evidence_tier="HEURISTIC_RESIDUAL",
    independently_qualified=False,
    source_revision="20261022-acc2-read-only",
)


def _claim_signature(occ: object) -> tuple:
    value = occ.value
    digest = (
        sha256(value.encode("utf8")).hexdigest()
        if isinstance(value, str) else None
    )
    return occ.display_path, occ.start_byte, occ.end_byte, digest


def _same_candidate(a: CandidateResult, b: CandidateResult) -> bool:
    return (
        a.completeness == b.completeness
        and a.issues == b.issues
        and a.occurrences == b.occurrences
        and a.residual_regions == b.residual_regions
    )


def _claim_hits(candidate: CandidateResult, gold_fields: list[dict], offset: int) -> int:
    expected = Counter(
        (g["name"], g["startByte"], g["endByte"], g["decodedSha256"])
        for g in gold_fields
    )
    actual = Counter(
        (path, start + offset, end + offset, digest)
        for path, start, end, digest in map(_claim_signature, candidate.occurrences)
    )
    return sum((expected & actual).values())


def _validate_publisher(raw: bytes, oracle: bytes) -> dict:
    if sha256(oracle).hexdigest() != PUBLISHER_PIN_SHA256:
        raise ValueError("PUBLISHER_ORACLE_PIN_MISMATCH")
    doc = json.loads(oracle.decode("utf8", "strict"))
    if (
        sha256(raw).hexdigest() != doc["canonicalSourceSha256"]
        or len(raw) != doc["canonicalSourceBytes"]
    ):
        raise ValueError("PUBLISHER_SOURCE_PIN_MISMATCH")
    if doc.get("sourceClass") is None:
        raise ValueError("PUBLISHER_SOURCE_CLASS_MISSING")
    claims = doc["publisherExpectedFields"]
    if doc.get("rows") != len(claims) or sum(len(c) for c in claims) != doc["fieldClaims"]:
        raise ValueError("PUBLISHER_ROW_COUNT_MISMATCH")
    # Prevent a mislabeled original span from being counted as independent truth.
    for row in claims:
        for field in row:
            a, b = field["startByte"], field["endByte"]
            if not 0 <= a <= b <= len(raw):
                raise ValueError("PUBLISHER_SPAN_OUT_OF_BOUNDS")
            try:
                raw[:a].decode("utf8", "strict")
                raw[:b].decode("utf8", "strict")
            except UnicodeDecodeError as error:
                raise ValueError("PUBLISHER_SPAN_SPLITS_UTF8") from error
            if sha256(raw[a:b]).hexdigest() != field["lexemeSha256"]:
                raise ValueError("PUBLISHER_SPAN_HASH_MISMATCH")
    return doc


def score_publisher_reference(source: Path, oracle: Path) -> dict:
    raw_bytes = source.read_bytes()
    original = raw_bytes.decode("utf8", "strict")
    doc = _validate_publisher(raw_bytes, oracle.read_bytes())
    first_ns = perf_counter_ns()
    batch = parse_security_batch(
        original, max_events=500, max_bytes=65536,
        parser=parse_security_multipass
    )
    if len(batch.frames) != doc["rows"]:
        raise ValueError("PUBLISHER_SOURCE_EVENT_COUNT_MISMATCH")
    product = preview_batch(original)
    if product["eventCount"] != doc["rows"] or product["sourceSha256"] != sha256(raw_bytes).hexdigest():
        raise ValueError("PRODUCT_PREVIEW_SOURCE_MISMATCH")

    funnel = run_funnel_batch(frame.raw for frame in batch.frames)
    per_row: list[dict] = []
    candidate_counts = 0
    hard_rejections = 0
    selection_changes = 0
    unverified_extra = 0
    status_counts = Counter()
    product_matches = 0
    shadow_matches = 0
    for index, frame in enumerate(batch.frames):
        golds = doc["publisherExpectedFields"][index]
        # This is the actual public preview guard. Framing/schema issues must
        # *never* be turned into SOURCE_PARSED by the candidate scorer.
        protected = any(
            issue.startswith(("FRAMING_", "SCHEMA_"))
            for issue in frame.event.issues
        )
        live_event = frame.event if protected else funnel.selected[index]
        previewed = product["events"][index]["preview"]
        if (
            previewed["status"] != live_event.status
            or previewed["issues"] != live_event.issues
            or len(previewed["spans"]) != len(live_event.value_spans)
        ):
            raise ValueError("PRODUCT_PREVIEW_SELECTION_MISMATCH")
        baseline = candidate_from_event(frame.event, EVIDENCE)
        accepted = candidate_from_event(live_event, EVIDENCE)

        # Fixed pool = product-selected candidate, its protected framing
        # baseline, and research beam=4 on identical pinned source/learned
        # hypotheses. The alternative beam does not alter product execution.
        exploratory = run_funnel_event(
            frame.raw, funnel.hypotheses, config=FunnelConfig(beam_width=4)
        )
        pool: list[CandidateResult] = [accepted]
        for candidate in [baseline, *(
            candidate_from_event(item.event, EVIDENCE)
            for item in exploratory.beam
        )]:
            if not any(_same_candidate(candidate, prior) for prior in pool):
                pool.append(candidate)
        decision = choose_shadow(frame.raw, pool, baseline)
        candidate_counts += len(pool)
        hard_rejections += sum(not score.valid for score in decision.scores)
        if decision.selected_index is None:
            raise ValueError("NO_VALID_SHADOW_CANDIDATE")
        winner = pool[decision.selected_index]
        if winner.completeness != accepted.completeness and protected:
            raise ValueError("PROTECTED_SOURCE_STATUS_CHANGED")
        if not _same_candidate(winner, accepted):
            selection_changes += 1
        gold_count = len(golds)
        baseline_hit = _claim_hits(accepted, golds, frame.start_byte)
        shadow_hit = _claim_hits(winner, golds, frame.start_byte)
        product_matches += baseline_hit
        shadow_matches += shadow_hit
        # Not counted as false positives without a complete field oracle.
        unverified_extra += max(0, len(accepted.occurrences) - gold_count)
        status_counts[accepted.completeness] += 1
        per_row.append({
            "published_claim_count": gold_count,
            "product_exact_claims": baseline_hit,
            "shadow_exact_claims": shadow_hit,
            "protected_framing_or_schema": protected,
            "product_source_complete": accepted.completeness == "SOURCE_PARSED",
            "shadow_source_complete": winner.completeness == "SOURCE_PARSED",
        })

    total_span_bytes = sum(
        frame.end_byte - frame.start_byte for frame in batch.frames
    ) + sum(separator.end_byte - separator.start_byte for separator in batch.separators)
    if total_span_bytes != len(raw_bytes):
        raise ValueError("PUBLISHER_SOURCE_BYTE_ACCOUNTING_MISMATCH")

    elapsed_ms = (perf_counter_ns() - first_ns) / 1e6
    return {
        "contract": "parser-studio.acc2.publisher-w3c-digest.v0.1",
        "oracle_provenance": "PUBLISHER_AUTHORED_STANDARD_REFERENCE_NOT_VENDOR_WIRE_NOT_BLIND",
        "publisher_oracle_sha256": sha256(oracle.read_bytes()).hexdigest(),
        "source_sha256": sha256(raw_bytes).hexdigest(),
        "source_bytes": len(raw_bytes),
        "event_rows": len(batch.frames),
        "published_field_claims": doc["fieldClaims"],
        "product_published_claims_exact": product_matches,
        "shadow_published_claims_exact": shadow_matches,
        "uncertified_extra_product_claims": unverified_extra,
        "protected_frame_count": sum(row["protected_framing_or_schema"] for row in per_row),
        "source_status_counts": dict(sorted(status_counts.items())),
        "research_candidate_snapshots": candidate_counts,
        "shadow_hard_gate_rejections": hard_rejections,
        "shadow_selection_changed": selection_changes,
        "all_original_bytes_accounted": total_span_bytes == len(raw_bytes),
        "independent_claims_scored": True,
        "complete_vendor_field_oracle": False,
        "field_precision_recall_f1": "UNSCORABLE_WITH_PARTIAL_PUBLISHER_ORACLE",
        "manufacturer_holdout": "NOT_AVAILABLE",
        "runtime_performance_p99": "NOT_ESTIMABLE_FROM_4_REFERENCE_ROWS",
        "elapsed_ms_includes_setup": round(elapsed_ms, 3),
        "public_or_target_deployment_modified": False,
        "row_claim_counts_only": per_row,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Score pinned publisher W3C claims without printing source")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = score_publisher_reference(args.source, args.oracle)
    report = json.dumps(result, sort_keys=True, ensure_ascii=True, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
